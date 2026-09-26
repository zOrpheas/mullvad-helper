// Privileged operation bodies (install / repair / wg-quick / systemd / ...).
use super::ops::{valid_tunnel, valid_unit, wg_dir};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Copy a staging file to /etc/wireguard/<name>.conf as root-only 0600.
pub fn install_config(staging: &str, name: &str) -> Result<String, String> {
    if !valid_tunnel(name) {
        return Err("invalid tunnel name".into());
    }
    let src = std::path::Path::new(staging);
    if !src.is_file() {
        return Err("staging file not found".into());
    }
    // Configs are ~1 KB; anything huge is not a WireGuard config.
    let meta = fs::metadata(src).map_err(|e| format!("cannot stat staging file: {e}"))?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err("staging file too large".into());
    }
    let dir = wg_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create /etc/wireguard: {e}"))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot chmod /etc/wireguard: {e}"))?;
    let dest = dir.join(format!("{name}.conf"));
    fs::copy(src, &dest).map_err(|e| format!("copy failed: {e}"))?;
    if let Err(e) = fs::set_permissions(&dest, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(&dest);
        return Err(format!("cannot chmod config: {e}"));
    }
    let ok = Command::new("chown")
        .arg("root:root")
        .arg(&dest)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err("cannot chown config to root".into());
    }
    Ok(format!("installed {}", dest.display()))
}

pub fn repair_perms() -> Result<String, String> {
    let dir = wg_dir();
    if !dir.exists() {
        return Err("/etc/wireguard does not exist".into());
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod dir failed: {e}"))?;
    let entries = fs::read_dir(&dir).map_err(|e| format!("cannot list /etc/wireguard: {e}"))?;
    let mut fixed = 0;
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("conf") {
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
            let _ = Command::new("chown").arg("root:root").arg(&p).status();
            fixed += 1;
        }
    }
    Ok(format!("permissions repaired ({fixed} configs)"))
}

pub fn wg_quick(up: bool, name: &str) -> Result<String, String> {
    if !valid_tunnel(name) {
        return Err("invalid tunnel name".into());
    }
    let arg = if up { "up" } else { "down" };
    // Capture rather than inherit so the caller can show real diagnostics.
    let out = Command::new("wg-quick")
        .arg(arg)
        .arg(name)
        .output()
        .map_err(|e| format!("wg-quick not found: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let so = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "wg-quick {arg} {name} failed: {}{}",
            so.trim(),
            err.trim()
        ));
    }
    Ok(format!("wg-quick {arg} {name} ok"))
}

pub fn systemctl(enable: bool, unit: &str) -> Result<String, String> {
    if !valid_unit(unit) {
        return Err("only wg-quick@<tunnel>.service units are allowed".into());
    }
    let arg = if enable { "enable" } else { "disable" };
    let st = Command::new("systemctl")
        .arg(arg)
        .arg(unit)
        .status()
        .map_err(|e| format!("systemctl failed: {e}"))?;
    if !st.success() {
        return Err(format!("systemctl {arg} {unit} failed"));
    }
    Ok(format!("systemctl {arg} {unit} ok"))
}

/// Delete an installed config. Refuses while the tunnel is up so we never
/// yank a running interface out from under the user.
pub fn remove_config(name: &str) -> Result<String, String> {
    if !valid_tunnel(name) {
        return Err("invalid tunnel name".into());
    }
    let target = wg_dir().join(format!("{name}.conf"));
    if !target.is_file() {
        return Err("configuration not found".into());
    }
    // Must live directly in /etc/wireguard (no traversal, already validated).
    let wg_path = wg_dir();
    if let Some(parent) = target.parent() {
        if parent != wg_path.as_path() {
            return Err("refusing to delete outside /etc/wireguard".into());
        }
    }
    let running = Command::new("wg")
        .args(["show", name, "dump"])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false);
    if running {
        return Err(format!(
            "{name} is currently connected — disconnect it first"
        ));
    }
    fs::remove_file(&target).map_err(|e| format!("could not delete configuration: {e}"))?;
    let _ = Command::new("systemctl")
        .arg("disable")
        .arg(format!("wg-quick@{name}.service"))
        .status();
    Ok(format!("removed {name}"))
}

