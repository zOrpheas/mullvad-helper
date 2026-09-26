//! DNS detection for Arch Linux. Never overwrites resolv.conf blindly.
use crate::command::CommandRunner;
use std::sync::Arc;
use mullvad_helper_core::{DnsArchitecture, DnsInfo};

#[derive(Debug, Clone)]
pub struct DnsService<R: CommandRunner> {
    runner: Arc<R>,
}

impl<R: CommandRunner> DnsService<R> {
    pub fn new(runner: Arc<R>) -> Self {
        Self { runner }
    }
    pub async fn detect(&self) -> DnsInfo {
        let resolved_active = self.is_active("systemd-resolved.service").await;
        let nm_active = self.is_active("NetworkManager.service").await;
        let resolv_target = self.read_resolv_target().await;
        let (resolvconf_present, provider_hint) = self.resolvconf_provider().await;
        let target_lower = resolv_target.clone().unwrap_or_default().to_lowercase();
        let uses_stub = target_lower.contains("systemd") || target_lower.contains("stub-resolv");
        let uses_resolvconf_run = target_lower.contains("resolvconf");
        let architecture = if resolved_active && uses_stub {
            if resolvconf_present && provider_hint.as_deref() == Some("openresolv")
                && self.openresolv_shim_conflict().await
            {
                DnsArchitecture::SystemdResolvedWithIncompatibleResolvconf
            } else {
                DnsArchitecture::SystemdResolved
            }
        } else if uses_resolvconf_run || provider_hint.is_some() {
            DnsArchitecture::Openresolv
        } else if nm_active {
            DnsArchitecture::NetworkManagerOnly
        } else if resolv_target.is_some() {
            DnsArchitecture::StaticResolvConf
        } else {
            DnsArchitecture::Unknown
        };
        let (summary, problem) = match architecture {
            DnsArchitecture::SystemdResolved => (
                "System uses systemd-resolved (compatible).".to_string(), None,
            ),
            DnsArchitecture::SystemdResolvedWithIncompatibleResolvconf => (
                "systemd-resolved is active but openresolv shadows resolvconf.".to_string(),
                Some("WireGuard connected, but DNS could not be configured because your system uses systemd-resolved while openresolv is currently installed.".to_string()),
            ),
            DnsArchitecture::Openresolv => (
                "System uses openresolv for DNS updates.".to_string(), None,
            ),
            DnsArchitecture::NetworkManagerOnly => (
                "NetworkManager manages DNS.".to_string(), None,
            ),
            DnsArchitecture::StaticResolvConf => (
                "Using a static /etc/resolv.conf file.".to_string(),
                Some("No DNS manager detected. WireGuard DNS entries may not be applied automatically.".to_string()),
            ),
            DnsArchitecture::Unknown => (
                "DNS setup could not be determined.".to_string(),
                Some("DNS setup is unknown; check Technical details.".to_string()),
            ),
        };
        DnsInfo {
            architecture, resolv_conf_target: resolv_target, resolved_active,
            network_manager_active: nm_active, resolvconf_present,
            resolvconf_provider_hint: provider_hint, summary, problem,
        }
    }
    async fn is_active(&self, unit: &str) -> bool {
        if let Ok(o) = self.runner.run("systemctl", &["is-active", unit]).await {
            return o.success() && o.stdout.trim() == "active";
        }
        false
    }
    async fn read_resolv_target(&self) -> Option<String> {
        if let Ok(o) = self.runner.run("readlink", &["/etc/resolv.conf"]).await {
            if o.success() {
                let t = o.stdout.trim().to_string();
                if !t.is_empty() {
                    return Some(t);
                }
            }
        }
        None
    }
    async fn resolvconf_provider(&self) -> (bool, Option<String>) {
        let which = self.runner.run("sh", &["-c", "command -v resolvconf"]).await;
        let present = which.map(|o| o.success()).unwrap_or(false);
        if !present {
            return (false, None);
        }
        if let Ok(o) = self.runner.run("pacman", &["-Qo", "/usr/bin/resolvconf"]).await {
            let out = format!("{} {}", o.stdout, o.stderr).to_lowercase();
            if out.contains("systemd-resolvconf") || out.contains("systemd") {
                return (true, Some("systemd-resolvconf".to_string()));
            }
            if out.contains("openresolv") {
                return (true, Some("openresolv".to_string()));
            }
        }
        (true, None)
    }
    async fn openresolv_shim_conflict(&self) -> bool {
        if let Ok(o) = self.runner.run("sh", &["-c", "resolvconf --version"]).await {
            let blob = format!("{} {}", o.stdout, o.stderr).to_lowercase();
            if blob.contains("openresolv") {
                return true;
            }
        }
        if let Ok(o) = self.runner.run("pacman", &["-Q", "openresolv"]).await {
            if o.success() {
                return true;
            }
        }
        false
    }
    /// Suggested pacman fix; caller must confirm with user before running.
    pub fn suggested_resolvconf_fix(info: &DnsInfo) -> Option<Vec<String>> {
        if info.architecture == DnsArchitecture::SystemdResolvedWithIncompatibleResolvconf {
            return Some(vec![
                "sudo pacman -Rns openresolv".to_string(),
                "sudo pacman -S systemd-resolvconf".to_string(),
                "sudo systemctl enable --now systemd-resolved.service".to_string(),
                "sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf".to_string(),
            ]);
        }
        None
    }
}
