//! WireGuard control via system tools (wg / wg-quick).
use crate::command::CommandRunner;
use crate::errors::{TunnelError, explain_wg_quick_error};
use std::sync::Arc;
use tracing::info;
use mullvad_helper_core::redact::redact_secrets;

#[derive(Debug, Clone)]
pub struct WireGuardService<R: CommandRunner> {
    runner: Arc<R>,
    privileged: Arc<crate::privilege::PrivilegeService<R>>,
}

impl<R: CommandRunner> WireGuardService<R> {
    pub fn new(runner: Arc<R>, privileged: Arc<crate::privilege::PrivilegeService<R>>) -> Self {
        Self { runner, privileged }
    }
    fn safe_name(name: &str) -> Result<(), TunnelError> {
        mullvad_helper_core::parser::validate_tunnel_name(name).map_err(|e| {
            TunnelError::friendly(
                format!("Invalid tunnel name '{name}'. Use only letters, numbers, - and _."),
                e.to_string(),
            )
        })
    }
    /// wg-quick up <name> (privileged).
    pub async fn connect(&self, name: &str) -> Result<String, TunnelError> {
        Self::safe_name(name)?;
        info!("wg-quick up {name}");
        let res = self.privileged.wg_quick_up(name).await.map_err(|e| {
            TunnelError::friendly(explain_wg_quick_error(&e.to_string()), e.to_string())
        })?;
        if !res.success() {
            let tech = redact_secrets(&format!("{}{}", res.stdout, res.stderr));
            return Err(TunnelError::friendly(explain_wg_quick_error(&res.stderr), tech));
        }
        Ok(redact_secrets(&res.stdout))
    }
    /// wg-quick down <name> (privileged).
    pub async fn disconnect(&self, name: &str) -> Result<String, TunnelError> {
        Self::safe_name(name)?;
        info!("wg-quick down {name}");
        let res = self.privileged.wg_quick_down(name).await.map_err(|e| {
            TunnelError::friendly("The tunnel could not be stopped.", e.to_string())
        })?;
        if !res.success() {
            let tech = redact_secrets(&format!("{}{}", res.stdout, res.stderr));
            return Err(TunnelError::friendly("The tunnel could not be stopped.", tech));
        }
        Ok(redact_secrets(&res.stdout))
    }
    /// Sanitised status via the privileged helper.
    ///
    /// `wg show <iface> dump` requires CAP_NET_ADMIN, which the GUI does not
    /// have — that was why a *running* tunnel used to show up as "Disconnected
    /// / not running". The helper runs it as root and returns only
    /// `peers \t handshake_epoch \t rx \t tx`, never key material.
    pub async fn status(&self, name: &str) -> Result<mullvad_helper_core::WireGuardStatus, TunnelError> {
        Self::safe_name(name)?;
        let out = self
            .privileged
            .wg_status(name)
            .await
            .map_err(|e| TunnelError::friendly("Could not query WireGuard status.", e.to_string()))?;
        if !out.success() {
            // Helper told us the interface is not available => not up.
            return Ok(mullvad_helper_core::WireGuardStatus {
                interface_exists: false,
                interface_up: false,
                peer_count: 0,
                latest_handshake_secs_ago: None,
                rx_bytes: 0,
                tx_bytes: 0,
            });
        }
        Ok(parse_wg_status(&out.stdout))
    }
    /// List active wg interfaces via `wg show interfaces`.
    pub async fn active_interfaces(&self) -> Vec<String> {
        let Ok(out) = self.runner.run("wg", &["show", "interfaces"]).await else {
            return vec![];
        };
        if !out.success() {
            return vec![];
        }
        out.stdout.split_whitespace().map(|s| s.to_string()).filter(|s| !s.is_empty()).collect()
    }
}

/// Parse `wg show dump`: line 1 = iface, rest = peers.
pub fn parse_wg_dump(stdout: &str) -> mullvad_helper_core::WireGuardStatus {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    let Some(_iface) = lines.next() else {
        return mullvad_helper_core::WireGuardStatus {
            interface_exists: false, interface_up: false, peer_count: 0,
            latest_handshake_secs_ago: None, rx_bytes: 0, tx_bytes: 0,
        };
    };
    let mut peer_count = 0usize;
    let mut latest: Option<u64> = None;
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in lines {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 7 {
            continue;
        }
        peer_count += 1;
        let hs: u64 = cols[4].trim().parse().unwrap_or(0);
        if hs > 0 {
            let ago = now.saturating_sub(hs);
            latest = Some(latest.map_or(ago, |m: u64| m.min(ago)));
        }
        rx += cols[5].trim().parse().unwrap_or(0);
        tx += cols[6].trim().parse().unwrap_or(0);
    }
    mullvad_helper_core::WireGuardStatus {
        interface_exists: true, interface_up: true, peer_count,
        latest_handshake_secs_ago: latest, rx_bytes: rx, tx_bytes: tx,
    }
}

/// Parse the helper's sanitised `wg-status` line: `peers \t hs_epoch \t rx \t tx`.
pub fn parse_wg_status(stdout: &str) -> mullvad_helper_core::WireGuardStatus {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cols: Vec<&str> = stdout.trim().split('\t').collect();
    if cols.len() < 4 {
        return mullvad_helper_core::WireGuardStatus {
            interface_exists: false,
            interface_up: false,
            peer_count: 0,
            latest_handshake_secs_ago: None,
            rx_bytes: 0,
            tx_bytes: 0,
        };
    }
    let peers: usize = cols[0].trim().parse().unwrap_or(0);
    let hs: u64 = cols[1].trim().parse().unwrap_or(0);
    let rx: u64 = cols[2].trim().parse().unwrap_or(0);
    let tx: u64 = cols[3].trim().parse().unwrap_or(0);
    mullvad_helper_core::WireGuardStatus {
        interface_exists: true,
        interface_up: true,
        peer_count: peers,
        latest_handshake_secs_ago: if hs == 0 { None } else { Some(now.saturating_sub(hs)) },
        rx_bytes: rx,
        tx_bytes: tx,
    }
}

/// Overall health from status + connectivity probes.
pub fn health_from(st: &mullvad_helper_core::WireGuardStatus, internet_ok: bool, vpn_ip_seen: bool) -> mullvad_helper_core::TunnelHealth {
    use mullvad_helper_core::TunnelHealth;
    if !st.interface_exists {
        return TunnelHealth::Disconnected;
    }
    match st.latest_handshake_secs_ago {
        None => TunnelHealth::WaitingForHandshake,
        Some(ago) if ago > 180 => TunnelHealth::WaitingForHandshake,
        _ => {
            if internet_ok && vpn_ip_seen {
                TunnelHealth::Connected
            } else if internet_ok || vpn_ip_seen {
                TunnelHealth::Degraded
            } else {
                TunnelHealth::WaitingForHandshake
            }
        }
    }
}
