//! Privilege boundary.
//!
//! The GUI/CLI NEVER run as root. Every privileged action goes through
//! PrivilegeService, which shells out to the minimal helper binary
//! `mullvad-helper-privileged` via pkexec (polkit). Each helper invocation
//! performs exactly ONE narrowly-scoped operation and validates its
//! arguments (tunnel names, unit names) before touching the system.

use crate::command::{CommandOutput, CommandRunner};
use crate::daemon_client::{self, Daemon};
use std::sync::Arc;
use std::sync::Mutex;

pub const HELPER_BIN: &str = "mullvad-helper-privileged";

/// Resolve the helper binary path: prefer a helper sitting next to the
/// current executable (dev: target/debug|release), then PATH, else the
/// system path. Fixes the classic "pkexec can't find my dev binary" bug.
pub fn resolve_helper_path() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(HELPER_BIN);
            if sibling.is_file() {
                return sibling.to_string_lossy().to_string();
            }
        }
    }
    for dir in ["/usr/bin", "/usr/local/bin"] {
        let p = format!("{dir}/{HELPER_BIN}");
        if std::path::Path::new(&p).is_file() {
            return p;
        }
    }
    HELPER_BIN.to_string()
}

/// Only these helper verbs exist. Adding a new privileged capability
/// requires adding a verb HERE + in the helper binary + docs.
#[derive(Debug, Clone, Copy)]
pub enum PrivilegedVerb {
    InstallConfig,
    RepairPerms,
    WgQuickUp,
    WgQuickDown,
    SystemctlEnable,
    SystemctlDisable,
    RemoveConfig,
    InstallPackages,
    ListConfigs,
    WgStatus,
}

impl PrivilegedVerb {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InstallConfig => "install-config",
            Self::RepairPerms => "repair-perms",
            Self::WgQuickUp => "wg-quick-up",
            Self::WgQuickDown => "wg-quick-down",
            Self::SystemctlEnable => "systemctl-enable",
            Self::SystemctlDisable => "systemctl-disable",
            Self::RemoveConfig => "remove-config",
            Self::InstallPackages => "install-packages",
            Self::ListConfigs => "list-configs",
            Self::WgStatus => "wg-status",
        }
    }

    /// Background polls: must never pop up a password dialog on their own.
    fn is_read_only(&self) -> bool {
        matches!(self, Self::ListConfigs | Self::WgStatus)
    }
}

#[derive(Debug, Clone)]
pub struct PrivilegeService<R: CommandRunner> {
    runner: Arc<R>,
    /// Override helper binary path (tests / dev).
    pub helper_path: String,
    /// When true, call helper directly (already root in tests) w/o pkexec.
    pub direct: bool,
    /// GUI session mode: authorize once at launch via [`Self::unlock`] and
    /// never fall back to a per-call pkexec prompt.
    pub session: bool,
    /// Persistent daemon (one polkit prompt for the whole session).
    daemon: Arc<Mutex<Option<Daemon>>>,
}

impl<R: CommandRunner> PrivilegeService<R> {
    pub fn new(runner: Arc<R>) -> Self {
        Self {
            runner,
            helper_path: resolve_helper_path(),
            direct: false,
            session: false,
            daemon: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_helper(runner: Arc<R>, helper_path: &str, direct: bool) -> Self {
        Self {
            runner,
            helper_path: helper_path.to_string(),
            direct,
            session: false,
            daemon: Arc::new(Mutex::new(None)),
        }
    }

    /// Request administrator access once (one polkit prompt) and keep the
    /// helper daemon alive for the session, so connect/disconnect never ask
    /// for the password again.
    pub fn unlock(&self) -> Result<(), String> {
        if self.direct {
            return Ok(());
        }
        if self.is_unlocked() {
            return Ok(());
        }
        // Reap a dead handle first: its Drop would otherwise send "quit" to
        // (and unlink the socket of) the daemon we are about to start.
        if let Some(mut d) = self.daemon.lock().unwrap().take() {
            d.shutdown();
        }
        let daemon = Daemon::start(&self.helper_path)?;
        *self.daemon.lock().unwrap() = Some(daemon);
        Ok(())
    }

    /// Are we already authorized (daemon answering)?
    pub fn is_unlocked(&self) -> bool {
        if self.direct {
            return true;
        }
        daemon_client::is_unlocked()
    }

    /// True when the session was rejected/dismissed (so the UI can show a
    /// "Unlock" affordance instead of silently falling back to prompting).
    pub fn has_daemon(&self) -> bool {
        self.daemon.lock().unwrap().is_some()
    }

    /// Stop the helper daemon (called when the app exits).
    pub fn shutdown(&self) {
        if let Some(mut d) = self.daemon.lock().unwrap().take() {
            d.shutdown();
        }
    }

    async fn call(
        &self,
        verb: PrivilegedVerb,
        args: &[&str],
    ) -> Result<CommandOutput, std::io::Error> {
        if self.direct {
            let mut full = vec![verb.as_str()];
            full.extend(args);
            return self.runner.run(&self.helper_path, &full).await;
        }
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        if self.session {
            if !daemon_client::is_unlocked() {
                let denied = |e: String| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e);
                if verb.is_read_only() {
                    return Err(denied("administrator access not granted".into()));
                }
                // Access was refused at launch (or the daemon died): ask once
                // more for this explicit user action; the daemon then persists.
                self.unlock().map_err(denied)?;
            }
            return daemon_client::request(verb.as_str(), &owned);
        }
        // Preferred path: reuse the session daemon (no password prompt).
        if daemon_client::is_unlocked() {
            match daemon_client::request(verb.as_str(), &owned) {
                Ok(out) => return Ok(out),
                Err(_) => {
                    // Socket died (idle timeout / helper restarted): drop the
                    // stale handle and fall through to one-shot.
                    if let Some(mut d) = self.daemon.lock().unwrap().take() {
                        d.shutdown();
                    }
                }
            }
        }
        // Fallback: one-shot pkexec (will prompt).
        let mut full: Vec<&str> = vec![&self.helper_path, verb.as_str()];
        full.extend(args);
        self.runner.run("pkexec", &full).await
    }

    /// Copy staging file into /etc/wireguard/<name>.conf, mode 0600.
    pub async fn install_config(
        &self,
        staging_path: &str,
        name: &str,
    ) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::InstallConfig, &[staging_path, name])
            .await
    }

    pub async fn repair_perms(&self) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::RepairPerms, &[]).await
    }

    pub async fn wg_quick_up(&self, name: &str) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::WgQuickUp, &[name]).await
    }

    pub async fn wg_quick_down(&self, name: &str) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::WgQuickDown, &[name]).await
    }

    pub async fn systemctl_enable(&self, unit: &str) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::SystemctlEnable, &[unit]).await
    }

    pub async fn systemctl_disable(&self, unit: &str) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::SystemctlDisable, &[unit]).await
    }

    /// Delete an installed config (helper validates the name).
    pub async fn remove_config(&self, name: &str) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::RemoveConfig, &[name]).await
    }

    /// Install pacman packages (helper allow-lists package names).
    pub async fn install_packages(&self, packages: &[String]) -> Result<CommandOutput, std::io::Error> {
        let refs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();
        self.call(PrivilegedVerb::InstallPackages, &refs).await
    }

    /// Names of installed configs (contents never leave /etc/wireguard).
    pub async fn list_configs(&self) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::ListConfigs, &[]).await
    }

    /// Sanitised `wg show <name> dump` (private key never returned):
    /// `peers \t latest_handshake_epoch \t rx \t tx`.
    pub async fn wg_status(&self, name: &str) -> Result<CommandOutput, std::io::Error> {
        self.call(PrivilegedVerb::WgStatus, &[name]).await
    }
}
