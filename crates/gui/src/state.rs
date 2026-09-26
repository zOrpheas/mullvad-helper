// Snapshot model + jobs. Worker owns the snapshot; UI only renders it.
use std::sync::Arc;
use std::time::Instant;

pub type Runner = mullvad_helper_backend::command::SystemRunner;

#[derive(Clone)]
pub struct Backends {
    pub runner: Arc<Runner>,
    pub privs: Arc<mullvad_helper_backend::privilege::PrivilegeService<Runner>>,
}

pub fn backends() -> Backends {
    let runner: Arc<Runner> =
        Arc::new(mullvad_helper_backend::command::SystemRunner);
    let mut privs =
        mullvad_helper_backend::privilege::PrivilegeService::new(runner.clone());
    privs.session = true;
    Backends {
        runner,
        privs: Arc::new(privs),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Busy {
    #[default]
    Idle,
    Working(&'static str),
}

impl Busy {
    pub fn label(&self) -> Option<&'static str> {
        match self {
            Busy::Idle => None,
            Busy::Working(s) => Some(s),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub busy: Busy,
    pub active_iface: Option<String>,
    pub health: Health,
    pub status: Option<mullvad_helper_core::WireGuardStatus>,
    pub dns: Option<mullvad_helper_core::DnsInfo>,
    pub dns_fix: Option<Vec<String>>,
    pub configs: Vec<ConfigRow>,
    pub deps: Vec<mullvad_helper_core::DependencyCheck>,
    pub missing_packages: Vec<String>,
    pub doctor: Vec<mullvad_helper_core::DoctorCheck>,
    pub ip: Option<mullvad_helper_core::PublicIpInfo>,
    pub internet_ok: Option<bool>,
    pub notice: Option<Notice>,
    pub selected: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Health {
    #[default]
    Disconnected,
    Waiting,
    Degraded,
    Connected,
}

impl Health {
    pub fn label(self) -> &'static str {
        match self {
            Health::Disconnected => "Not protected",
            Health::Waiting => "Connecting…",
            Health::Degraded => "Connected, limited",
            Health::Connected => "Protected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Notice {
    pub error: bool,
    pub text: String,
    pub technical: Option<String>,
    /// When this notice was raised (kept for future auto-expiry rules).
    #[allow(dead_code)]
    pub at: Instant,
}

#[derive(Debug, Clone)]
pub struct ConfigRow {
    pub name: String,
    pub display: String,
    pub active: bool,
    pub autostart: bool,
}

#[derive(Debug)]
pub enum Job {
    Refresh,
    RefreshFull,
    Select(String),
    ToggleSelected,
    Connect(String),
    Disconnect(String),
    Import(std::path::PathBuf),
    CheckIp,
    Doctor,
    InstallMissing,
    SetAutostart { name: String, enabled: bool },
    Delete(String),
    RepairPerms,
    ApplyDnsFix,
    DismissNotice,
    /// Disconnect (if connected), then ask the UI to quit.
    Quit,
}

#[derive(Debug)]
pub enum UiMsg {
    Snap(Snapshot),
    /// Reserved for transient toast notifications (worker -> UI).
    #[allow(dead_code)]
    Toast(String),
    /// Bring the window back (tray click / second launch).
    Show,
    /// Disconnect and quit (tray menu).
    Kill,
    /// Worker finished `Job::Quit`: the tunnel is down, exit now.
    Quit,
}

pub fn ago(secs: u64) -> String {
    if secs < 5 {
        "just now".to_string()
    } else if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

/// A handshake older than this means "the server isn't answering".
pub const HANDSHAKE_STALE_SECS: u64 = 180;

/// Pure health decision: the single source of truth for the UI status.
///
/// Deliberately conservative — we only claim `Connected` when the interface
/// exists, the handshake is fresh, the internet is reachable AND we actually
/// saw a VPN public IP. An interface alone is NEVER enough.
pub fn health_of(
    status: Option<&mullvad_helper_core::WireGuardStatus>,
    internet_ok: Option<bool>,
    vpn_ip_seen: bool,
) -> Health {
    let Some(st) = status else {
        return Health::Disconnected;
    };
    if !st.interface_exists {
        return Health::Disconnected;
    }
    let fresh = st
        .latest_handshake_secs_ago
        .map(|s| s <= HANDSHAKE_STALE_SECS)
        .unwrap_or(false);
    if !fresh {
        return Health::Waiting;
    }
    match (internet_ok, vpn_ip_seen) {
        (Some(true), true) => Health::Connected,
        (Some(true), false) | (None, true) => Health::Degraded,
        // Fresh handshake but no probes yet: don't overpromise.
        _ => Health::Waiting,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mullvad_helper_core::WireGuardStatus;

    fn st(handshake: Option<u64>) -> WireGuardStatus {
        WireGuardStatus {
            interface_exists: true,
            interface_up: true,
            peer_count: 1,
            latest_handshake_secs_ago: handshake,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    #[test]
    fn interface_alone_is_never_connected() {
        // The classic bug: iface up, no handshake -> must not say Connected.
        assert_eq!(health_of(Some(&st(None)), Some(true), true), Health::Waiting);
    }

    #[test]
    fn stale_handshake_means_waiting() {
        assert_eq!(
            health_of(Some(&st(Some(HANDSHAKE_STALE_SECS + 1))), Some(true), true),
            Health::Waiting
        );
    }

    #[test]
    fn fresh_handshake_without_probes_is_waiting_not_connected() {
        assert_eq!(health_of(Some(&st(Some(8))), None, false), Health::Waiting);
    }

    #[test]
    fn connected_requires_internet_and_vpn_ip() {
        assert_eq!(health_of(Some(&st(Some(8))), Some(true), true), Health::Connected);
    }

    #[test]
    fn handshake_without_vpn_ip_is_degraded() {
        assert_eq!(health_of(Some(&st(Some(8))), Some(true), false), Health::Degraded);
    }

    #[test]
    fn no_interface_is_disconnected() {
        assert_eq!(health_of(None, Some(true), true), Health::Disconnected);
        let mut down = st(Some(1));
        down.interface_exists = false;
        assert_eq!(health_of(Some(&down), Some(true), true), Health::Disconnected);
    }

    #[test]
    fn ago_formatting() {
        assert_eq!(ago(1), "just now");
        assert_eq!(ago(42), "42s");
        assert_eq!(ago(125), "2m 5s");
    }
}

