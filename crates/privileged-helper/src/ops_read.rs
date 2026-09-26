// Read-only + package operations: list configs, sanitised wg status, pacman.
use super::ops::{allowed_package, valid_tunnel, wg_dir};
use std::fs;
use std::process::Command;

/// Names of installed tunnels. Names only — never file contents, because
/// /etc/wireguard is 0700 root-only and configs hold private keys.
pub fn list_configs() -> Result<String, String> {
    let dir = wg_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        // Missing directory simply means "nothing installed yet".
        Err(_) => return Ok(String::new()),
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("conf") {
                return None;
            }
            let stem = p.file_stem().and_then(|s| s.to_str())?.to_string();
            if valid_tunnel(&stem) {
                Some(stem)
            } else {
                None
            }
        })
        .collect();
    names.sort();
    Ok(names.join("\n"))
}

/// Sanitised status for one interface, as tab-separated values:
/// `peers \t latest_handshake_epoch \t rx_bytes \t tx_bytes`
///
/// We deliberately do NOT return `wg show dump` verbatim: its very first
/// field is the interface private key, which must never leave this process.
pub fn wg_status(name: &str) -> Result<String, String> {
    if !valid_tunnel(name) {
        return Err("invalid tunnel name".into());
    }
    let out = Command::new("wg")
        .args(["show", name, "dump"])
        .output()
        .map_err(|e| format!("wg not found: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "interface '{name}' is not available: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    // Drop the interface line entirely (field 0 is the private key).
    if lines.next().is_none() {
        return Err("no interface data returned".into());
    }
    let mut peers = 0u64;
    let mut latest = 0u64;
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in lines {
        // pubkey, psk, endpoint, allowed-ips, handshake, rx, tx, keepalive
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() < 7 {
            continue;
        }
        peers += 1;
        let hs: u64 = c[4].trim().parse().unwrap_or(0);
        if hs > latest {
            latest = hs;
        }
        rx += c[5].trim().parse().unwrap_or(0);
        tx += c[6].trim().parse().unwrap_or(0);
    }
    Ok(format!("{peers}\t{latest}\t{rx}\t{tx}"))
}

pub fn install_packages(pkgs: &[String]) -> Result<String, String> {
    if pkgs.is_empty() || pkgs.len() > 8 {
        return Err("no packages requested".into());
    }
    for p in pkgs {
        if !allowed_package(p) {
            return Err(format!("package '{p}' is not allowed"));
        }
    }
    let mut cmd = Command::new("pacman");
    cmd.arg("-S").arg("--needed").arg("--noconfirm");
    for p in pkgs {
        cmd.arg(p);
    }
    let st = cmd.status().map_err(|e| format!("pacman failed: {e}"))?;
    if !st.success() {
        return Err("pacman install failed".into());
    }
    Ok(format!("installed {}", pkgs.join(", ")))
}
