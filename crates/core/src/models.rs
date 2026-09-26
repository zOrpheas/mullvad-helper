//! Shared data models used by backend, CLI and GUI.
//!
//! Security rule: [`SafeConfigMetadata`] is the ONLY config-derived struct
//! allowed to reach the UI or logs. It never contains key material.

use serde::{Deserialize, Serialize};

/// Overall tunnel health as presented in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelHealth {
    /// No interface exists.
    Disconnected,
    /// Interface exists but no recent handshake.
    WaitingForHandshake,
    /// Interface + recent handshake but no internet yet / still verifying.
    Degraded,
    /// Interface + handshake + connectivity + VPN IP.
    Connected,
}

impl TunnelHealth {
    pub fn title(&self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::WaitingForHandshake => "Waiting for server",
            Self::Degraded => "Limited connectivity",
            Self::Connected => "Connected",
        }
    }
}

/// Safe, displayable metadata extracted from a WireGuard .conf file.
/// NEVER add private_key / preshared_key fields here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeConfigMetadata {
    /// Interface / tunnel name, e.g. `de-fra-wg-001`.
    pub name: String,
    /// Friendly display name derived from filename or Address, e.g. "Germany — Frankfurt".
    pub display_name: String,
    /// VPN endpoint host without port.
    pub endpoint_host: String,
    /// VPN endpoint port.
    pub endpoint_port: u16,
    /// Interface addresses (e.g. ["10.64.0.5/32", "fc00:bbbb::5/128"]).
    pub addresses: Vec<String>,
    /// DNS servers requested by the config.
    pub dns: Vec<String>,
    /// AllowedIPs (usually ["0.0.0.0/0", "::/0"] for full-tunnel).
    pub allowed_ips: Vec<String>,
    /// Whether PostUp/PreDown rules look like a kill-switch.
    pub kill_switch_detected: bool,
    /// Raw PostUp/PreUp/PostDown/PreDown lines (commands) for risk warning.
    /// Stored so UI can warn, but never auto-executed blindly.
    pub hook_commands: Vec<String>,
    /// Whether any hook looks risky (contains ; && || ` $() etc).
    pub hooks_look_risky: bool,
    /// Detected provider hint ("mullvad" if endpoint looks like Mullvad).
    pub provider_hint: Option<String>,
}

impl SafeConfigMetadata {
    pub fn short_location(&self) -> String {
        if self.display_name.is_empty() {
            self.name.clone()
        } else {
            self.display_name.clone()
        }
    }
}

/// A managed configuration known to the app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedConfig {
    pub metadata: SafeConfigMetadata,
    /// Absolute path, normally /etc/wireguard/<name>.conf
    pub installed_path: Option<String>,
    /// Whether systemd wg-quick@<name>.service is enabled (autostart on boot).
    pub autostart_enabled: bool,
    /// Whether currently active.
    pub active: bool,
}

/// DNS architecture variants relevant on Arch Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsArchitecture {
    SystemdResolved,
    SystemdResolvedWithIncompatibleResolvconf,
    Openresolv,
    NetworkManagerOnly,
    StaticResolvConf,
    Unknown,
}

impl DnsArchitecture {
    pub fn human_label(&self) -> &'static str {
        match self {
            Self::SystemdResolved => "systemd-resolved",
            Self::SystemdResolvedWithIncompatibleResolvconf => {
                "systemd-resolved with incompatible resolvconf"
            }
            Self::Openresolv => "openresolv",
            Self::NetworkManagerOnly => "NetworkManager",
            Self::StaticResolvConf => "manual /etc/resolv.conf",
            Self::Unknown => "unknown",
        }
    }
}

/// Full DNS detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub architecture: DnsArchitecture,
    /// Target of /etc/resolv.conf symlink, if it is a symlink.
    pub resolv_conf_target: Option<String>,
    /// Whether systemd-resolved service is active.
    pub resolved_active: bool,
    /// Whether NetworkManager is active.
    pub network_manager_active: bool,
    /// Whether `resolvconf` binary exists and its provider hint.
    pub resolvconf_present: bool,
    pub resolvconf_provider_hint: Option<String>,
    /// Human-readable summary.
    pub summary: String,
    /// If Some, DNS will likely break on connect and this explains why.
    pub problem: Option<String>,
}

/// One dependency check row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCheck {
    pub id: String,
    pub label: String,
    pub present: bool,
    pub detail: String,
    /// pacman package that provides it on Arch, if known.
    pub arch_package: Option<String>,
}

/// One doctor check row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub id: String,
    pub label: String,
    pub ok: bool,
    pub message: String,
}

/// WireGuard interface liveness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardStatus {
    pub interface_exists: bool,
    pub interface_up: bool,
    pub peer_count: usize,
    /// Seconds since latest handshake across peers, if known.
    pub latest_handshake_secs_ago: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Public IP lookup result. Never includes config contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIpInfo {
    pub ip: String,
    pub mullvad_exit: Option<bool>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub endpoint_used: String,
}
