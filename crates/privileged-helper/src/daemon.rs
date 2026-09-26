// Persistent root daemon: one polkit prompt for the whole GUI session.
//
// The GUI starts this with `pkexec mullvad-helper-privileged daemon <socket>`.
// Subsequent operations go over the socket instead of re-prompting.
//
// Threat model / confinement:
//   * the socket lives in $XDG_RUNTIME_DIR/mullvad-helper/ which is 0700 and
//     owned by the calling user, so only that user can traverse to it;
//   * every request re-runs the same validators as one-shot mode;
//   * `wg status` responses never contain key material (see ops_read).
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Deserialize)]
struct Request {
    id: Option<u64>,
    verb: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Serialize)]
struct Response {
    id: u64,
    status: i32,
    stdout: String,
    stderr: String,
}

const ACCEPT_TICK: Duration = Duration::from_millis(500);
const READ_TIMEOUT: Duration = Duration::from_secs(120);

pub fn run_daemon(socket_path: &str) {
    let path = PathBuf::from(socket_path);
    let _ = std::fs::remove_file(&path);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        // 0700 as defence in depth: the parent dir is already user-owned and
        // only the invoking user should ever reach this socket.
        let _ = std::fs::set_permissions(dir, fs_permissions(0o700));
    }
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("mullvad-helper-privileged: cannot bind socket: {e}");
            std::process::exit(1);
        }
    };
    // Prefer ownership by the invoking user when pkexec told us who that is.
    let owned = chown_socket_to_caller(&path);
    if owned {
        let _ = std::fs::set_permissions(&path, fs_permissions(0o600));
    } else {
        // Fall back to world-rw socket; access is still gated by the 0700
        // directory above, so only the user owning that dir can connect.
        let _ = std::fs::set_permissions(&path, fs_permissions(0o666));
    }
    let _ = listener.set_nonblocking(true);
    // Live exactly as long as the app: it holds our stdin pipe, so EOF means
    // it exited or crashed. Replaces an idle timeout that forced re-prompts.
    {
        let path = path.clone();
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
            let _ = std::fs::remove_file(&path);
            std::process::exit(0);
        });
    }
    // Signal readiness so the GUI stops waiting immediately.
    println!("READY");
    let _ = std::io::stdout().flush();

    'serve: loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                let mut reader = BufReader::new(match stream.try_clone() {
                    Ok(s) => s,
                    Err(_) => continue,
                });
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if line.trim().is_empty() {
                        continue;
                    }
                    match handle_line(&line) {
                        Err(_) => break 'serve, // "quit"
                        Ok(resp) => {
                            let mut out = serde_json::to_string(&resp).unwrap_or_default();
                            out.push('\n');
                            let _ = stream.write_all(out.as_bytes());
                            let _ = stream.flush();
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_TICK);
            }
            Err(e) => {
                eprintln!("mullvad-helper-privileged: accept failed: {e}");
                break;
            }
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// Returns Ok(response) to keep serving, Err(()) when asked to quit.
fn handle_line(line: &str) -> Result<Response, ()> {
    let id = serde_json::from_str::<Request>(line)
        .map(|r| r.id.unwrap_or(0))
        .unwrap_or(0);
    let req = match serde_json::from_str::<Request>(line) {
        Ok(r) => r,
        Err(e) => {
            return Ok(Response {
                id,
                status: 2,
                stdout: String::new(),
                stderr: format!("malformed request: {e}"),
            });
        }
    };
    if req.verb == "quit" {
        return Err(());
    }
    if req.verb == "ping" {
        return Ok(Response {
            id: req.id.unwrap_or(0),
            status: 0,
            stdout: "pong".into(),
            stderr: String::new(),
        });
    }
    let res = crate::ops::run(&req.verb, &req.args);
    Ok(match res {
        Ok(stdout) => Response {
            id: req.id.unwrap_or(0),
            status: 0,
            stdout,
            stderr: String::new(),
        },
        Err(stderr) => Response {
            id: req.id.unwrap_or(0),
            status: 1,
            stdout: String::new(),
            stderr,
        },
    })
}

fn fs_permissions(mode: u32) -> std::fs::Permissions {
    std::fs::Permissions::from_mode(mode)
}

fn chown_socket_to_caller(path: &Path) -> bool {
    // pkexec exports PKEXEC_UID for the invoking user. Chown the socket to
    // that user and keep it 0600 => owner-only access, no assumptions about
    // the user's gid.
    let Ok(uid) = std::env::var("PKEXEC_UID") else {
        return false;
    };
    if !uid.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let st = std::process::Command::new("chown")
        .args(["--", &uid])
        .arg(path)
        .status();
    matches!(st, Ok(s) if s.success())
}
