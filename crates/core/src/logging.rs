//! Local file logging with automatic secret redaction.
//!
//! Logs live under `~/.local/state/mullvad-helper/` (XDG_STATE_HOME aware).
//! Every line written through [`redacting_log`] is passed through
//! [`crate::redact::redact_secrets`] first so private keys can never
//! become a secret dump.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt};

/// Resolve the Mullvad Helper state dir, creating it if needed.
pub fn state_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("mullvad-helper");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local").join("state").join("mullvad-helper")
}

/// Initialise tracing -> stderr + redacted rolling-ish file log.
pub fn init_logging() -> PathBuf {
    let dir = state_dir();
    let _ = fs::create_dir_all(&dir);
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("mullvad_helper=info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
    dir
}

/// Append a (redacted) line to `mullvad-helper.log`.
pub fn append_log_line(line: &str) {
    let redacted = crate::redact::redact_secrets(line);
    let path = state_dir().join("mullvad-helper.log");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{redacted}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_ends_with_app_name() {
        assert!(state_dir().ends_with("mullvad-helper"));
    }

    /// The log writer must never persist key material, even if a caller
    /// accidentally passes raw wg-quick output through to it.
    #[test]
    fn log_writer_redacts_keys() {
        let dir = std::env::temp_dir().join("mullvad-helper-log-test");
        std::env::set_var("XDG_STATE_HOME", &dir);
        let _ = fs::remove_dir_all(&dir);
        append_log_line(
            "ERROR wg-quick failed: PrivateKey = SECRET1234567890SECRET1234567890SECRET=",
        );
        let written = fs::read_to_string(dir.join("mullvad-helper").join("mullvad-helper.log"))
            .expect("log file written");
        assert!(written.contains("[REDACTED]"));
        assert!(!written.contains("SECRET1234"));
        let _ = fs::remove_dir_all(&dir);
        std::env::remove_var("XDG_STATE_HOME");
    }
}
