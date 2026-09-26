//! Dependency detection: wg, wg-quick, resolvconf, systemd, etc.
use crate::command::CommandRunner;
use std::sync::Arc;
use mullvad_helper_core::DependencyCheck;

#[derive(Debug, Clone)]
pub struct DepsService<R: CommandRunner> {
    runner: Arc<R>,
}

impl<R: CommandRunner> DepsService<R> {
    pub fn new(runner: Arc<R>) -> Self {
        Self { runner }
    }
    async fn has_bin(&self, bin: &str) -> bool {
        let probe = format!("command -v {bin}");
        if let Ok(o) = self.runner.run("sh", &["-c", &probe]).await {
            return o.success();
        }
        false
    }
    async fn sys_active(&self, unit: &str) -> bool {
        if let Ok(o) = self.runner.run("systemctl", &["is-active", unit]).await {
            return o.success() && o.stdout.trim() == "active";
        }
        false
    }
    pub async fn check_all(&self) -> Vec<DependencyCheck> {
        let wg = self.has_bin("wg").await;
        let wg_quick = self.has_bin("wg-quick").await;
        let resolvconf = self.has_bin("resolvconf").await;
        let systemctl = self.has_bin("systemctl").await;
        let nft = self.has_bin("nft").await;
        let ip = self.has_bin("ip").await;
        let resolved = self.sys_active("systemd-resolved.service").await;
        let pacman = self.has_bin("pacman").await;
        vec![
            DependencyCheck {
                id: "wg".into(), label: "WireGuard tools (wg)".into(),
                present: wg, detail: if wg { "found".into() } else { "missing".into() },
                arch_package: Some("wireguard-tools".into()),
            },
            DependencyCheck {
                id: "wg-quick".into(), label: "wg-quick".into(),
                present: wg_quick, detail: if wg_quick { "found".into() } else { "missing".into() },
                arch_package: Some("wireguard-tools".into()),
            },
            DependencyCheck {
                id: "resolvconf".into(), label: "resolvconf shim".into(),
                present: resolvconf, detail: if resolvconf { "found".into() } else { "missing (DNS updates may fail)".into() },
                arch_package: Some("systemd-resolvconf / openresolv".into()),
            },
            DependencyCheck {
                id: "systemd".into(), label: "systemd".into(),
                present: systemctl, detail: if systemctl { "found".into() } else { "not found".into() },
                arch_package: None,
            },
            DependencyCheck {
                id: "systemd-resolved".into(), label: "systemd-resolved running".into(),
                present: resolved, detail: if resolved { "active".into() } else { "inactive".into() },
                arch_package: None,
            },
            DependencyCheck {
                id: "nftables".into(), label: "nftables (kill-switch support)".into(),
                present: nft, detail: if nft { "found".into() } else { "optional, missing".into() },
                arch_package: Some("nftables".into()),
            },
            DependencyCheck {
                id: "iproute2".into(), label: "iproute2 (ip)".into(),
                present: ip, detail: if ip { "found".into() } else { "missing".into() },
                arch_package: Some("iproute2".into()),
            },
            DependencyCheck {
                id: "pacman".into(), label: "pacman (Arch installer)".into(),
                present: pacman, detail: if pacman { "found".into() } else { "not on Arch?".into() },
                arch_package: None,
            },
        ]
    }
    /// Packages to suggest via pacman for missing tools.
    pub fn missing_arch_packages(checks: &[DependencyCheck]) -> Vec<String> {
        let mut out = vec![];
        let need_wg = checks.iter().any(|c| (c.id == "wg" || c.id == "wg-quick") && !c.present);
        if need_wg {
            out.push("wireguard-tools".to_string());
        }
        if checks.iter().any(|c| c.id == "resolvconf" && !c.present) {
            out.push("systemd-resolvconf".to_string());
        }
        out
    }
}
