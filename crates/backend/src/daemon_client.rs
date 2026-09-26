// Client for the privileged helper's daemon mode.
//
// The GUI starts one `pkexec mullvad-helper-privileged daemon <socket>` (one
// password prompt) and then reuses the socket for every privileged call, so
// the user is not re-authenticated on each connect/disconnect.
//
// Socket confinement: the socket lives in `$XDG_RUNTIME_DIR/mullvad-helper/`,
// created by the GUI as mode 0700 owned by the invoking user, and the daemon
// (root) chowns the socket back to that uid with mode 0600. Combined, only
// that user can reach it.
use crate::command::CommandOutput;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static SEQ: AtomicU64 = AtomicU64::new(1);

/// Directory holding the socket (0700, user-owned).
pub fn socket_dir() -> PathBuf {
    let base = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("mullvad-helper")
}

pub fn socket_path() -> PathBuf {
    socket_dir().join("helper.sock")
}

/// Create the 0700 dir the socket will live in (must run as the *user*,
/// before pkexec, so root inherits the right owner).
pub fn ensure_socket_dir() -> std::io::Result<PathBuf> {
    let dir = socket_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// JSON request/response shared with the helper (newline-delimited).
#[derive(serde::Serialize)]
struct Request<'a> {
    id: u64,
    verb: &'a str,
    args: &'a [String],
}

#[derive(serde::Deserialize)]
struct Response {
    #[serde(default)]
    #[allow(dead_code)]
    id: u64,
    status: i32,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
}

/// Blocking request over the local socket. The round-trip is microseconds
/// (same-host unix socket), so it is safe to call inline from async code.
pub fn request(verb: &str, args: &[String]) -> std::io::Result<CommandOutput> {
    let path = socket_path();
    let mut stream = std::os::unix::net::UnixStream::connect(&path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotConnected, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let req = Request {
        id: SEQ.fetch_add(1, Ordering::Relaxed),
        verb,
        args,
    };
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    let mut reader = BufReader::new(&stream);
    let mut out = String::new();
    reader.read_line(&mut out)?;
    let resp: Response = serde_json::from_str(out.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(CommandOutput {
        status: resp.status,
        stdout: resp.stdout,
        stderr: resp.stderr,
    })
}

/// Is a live daemon answering on the socket?
pub fn is_unlocked() -> bool {
    request("ping", &[])
        .map(|o| o.success() && o.stdout.contains("pong"))
        .unwrap_or(false)
}

/// Handle to a running daemon child so we can shut it down with the app.
#[derive(Debug)]
pub struct Daemon {
    child: Child,
    path: PathBuf,
}

impl Daemon {
    /// Start the helper daemon via pkexec (one polkit prompt) and wait until
    /// it reports READY. Returns None if the user dismissed the prompt.
    pub fn start(helper_path: &str) -> Result<Self, String> {
        ensure_socket_dir().map_err(|e| format!("cannot create socket dir: {e}"))?;
        // Drop any stale socket from a previous crash.
        let path = socket_path();
        if path.exists() {
            if is_unlocked() {
                // Someone already listening (e.g. second app instance).
                return Err("daemon-already-running".into());
            }
            let _ = std::fs::remove_file(&path);
        }
        let mut child = Command::new("pkexec")
            .arg(helper_path)
            .arg("daemon")
            .arg(&path)
            // The daemon exits when this pipe closes, i.e. when we exit or
            // crash, so root never outlives the app.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start pkexec: {e}"))?;

        // Wait for READY on stdout (stdout is a pipe held by us, so the
        // daemon never blocks on a terminal), or the socket to become live.
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if Instant::now() > deadline {
                let _ = child.kill();
                return Err("timed out waiting for authorization".into());
            }
            if is_unlocked() {
                // Drain output so systemctl/pacman (inherited stdio) can
                // never block the daemon on a full pipe.
                if let Some(mut o) = child.stdout.take() {
                    std::thread::spawn(move || std::io::copy(&mut o, &mut std::io::sink()));
                }
                if let Some(mut e) = child.stderr.take() {
                    std::thread::spawn(move || std::io::copy(&mut e, &mut std::io::sink()));
                }
                return Ok(Self { child, path });
            }
            // Did pkexec exit (user pressed cancel / polkit denied)?
            if let Ok(Some(status)) = child.try_wait() {
                let err = child
                    .stderr
                    .take()
                    .map(|s| {
                        use std::io::Read;
                        let mut b = String::new();
                        let mut r = s;
                        let _ = r.read_to_string(&mut b);
                        b
                    })
                    .unwrap_or_default();
                return Err(if status.success() {
                    "helper exited without starting a daemon".into()
                } else {
                    format!(
                        "authorization failed{}",
                        if err.trim().is_empty() {
                            String::new()
                        } else {
                            format!(": {}", err.trim())
                        }
                    )
                });
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    /// Ask the daemon to exit, then make sure the child is reaped.
    pub fn shutdown(&mut self) {
        let _ = request("quit", &[]);
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Best effort: a leaked root daemon would be a real security issue.
        let _ = request("quit", &[]);
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.path);
    }
}

