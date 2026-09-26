// Doctor: diagnose wg/DNS/perms/handshake/connectivity.
use crate::command::CommandRunner;
use crate::privilege::PrivilegeService;
use std::sync::Arc;
use mullvad_helper_core::DoctorCheck;

#[derive(Debug, Clone)]
pub struct Doctor<R: CommandRunner> {
    runner: Arc<R>,
    privileged: Arc<PrivilegeService<R>>,
}

impl<R: CommandRunner> Doctor<R> {
    pub fn new(runner: Arc<R>, privileged: Arc<PrivilegeService<R>>) -> Self {
        Self { runner, privileged }
    }

    async fn bin(&self, b: &str) -> bool {
        let probe = format!("command -v {b}");
        self.runner
            .run("sh", &["-c", &probe])
            .await
            .map(|o| o.success())
            .unwrap_or(false)
    }

    /// Interfaces currently up. `wg show interfaces` works without CAP_NET_ADMIN.
    async fn active_ifaces(&self) -> Vec<String> {
        match self.runner.run("wg", &["show", "interfaces"]).await {
            Ok(o) if o.success() => {
                o.stdout.split_whitespace().map(|s| s.to_string()).collect()
            }
            _ => vec![],
        }
    }

    fn row(id: &str, label: &str, ok: bool, message: String) -> DoctorCheck {
        DoctorCheck {
            id: id.into(),
            label: label.into(),
            ok,
            message,
        }
    }

    /// Real handshake age via the privileged helper — never a placeholder.
    async fn handshake_check(&self, active: Option<&str>) -> DoctorCheck {
        let Some(iface) = active else {
            return Self::row("handshake", "Recent handshake", false,
                "no active tunnel to verify".into());
        };
        match self.privileged.wg_status(iface).await {
            Ok(o) if o.success() => {
                match crate::wireguard::parse_wg_status(&o.stdout).latest_handshake_secs_ago {
                    Some(ago) if ago <= 180 => Self::row("handshake", "Recent handshake", true,
                        format!("{ago}s ago")),
                    Some(ago) => Self::row("handshake", "Recent handshake", false,
                        format!("{ago}s ago — server not responding")),
                    None => Self::row("handshake", "Recent handshake", false,
                        "none yet — waiting for the server to answer".into()),
                }
            }
            Ok(o) => Self::row("handshake", "Recent handshake", false,
                format!("could not read handshake: {}", o.stderr.trim())),
            Err(e) => Self::row("handshake", "Recent handshake", false,
                format!("could not query wg: {e}")),
        }
    }

    pub async fn run(&self, active_iface: Option<&str>) -> Vec<DoctorCheck> {
        let mut out = vec![];
        let wg = self.bin("wg").await;
        out.push(Self::row("wg-tools", "WireGuard tools installed", wg,
            if wg { "wg + wg-quick found".into() } else { "missing: install wireguard-tools".into() }));
        let sys = self.bin("systemctl").await;
        out.push(Self::row("systemd", "systemd running", sys,
            if sys { "systemctl available".into() } else { "systemctl not found".into() }));
        let resolved_active = self.runner
            .run("systemctl", &["is-active", "systemd-resolved.service"])
            .await
            .map(|o| o.success() && o.stdout.trim() == "active")
            .unwrap_or(false);
        out.push(Self::row("resolved", "systemd-resolved running", true,
            if resolved_active { "active".into() } else { "inactive (ok if using openresolv)".into() }));
        let resolvconf_ok = self.bin("resolvconf").await;
        out.push(Self::row("resolvconf", "resolvconf compatible", resolvconf_ok,
            if resolvconf_ok { "resolvconf shim present".into() }
            else { "no resolvconf shim; DNS= in .conf may not apply".into() }));
        let perms = self.runner
            .run("sh", &["-c", "stat -c %a /etc/wireguard 2>/dev/null"])
            .await
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_default();
        let perms_ok = perms == "700" || perms == "755" || perms == "750";
        out.push(Self::row("wgdir-perms", "/etc/wireguard permissions correct",
            perms_ok || perms.is_empty(),
            if perms.is_empty() { "directory not present yet".into() } else { format!("mode {perms}") }));
        // Interface: whichever tunnel is actually up (never "not running" for
        // a tunnel we can see in `wg show interfaces`).
        let active = match active_iface {
            Some(i) => Some(i.to_string()),
            None => self.active_ifaces().await.first().cloned(),
        };
        out.push(match &active {
            Some(iface) => Self::row("iface", "WireGuard interface available", true,
                format!("{iface} is up")),
            None => Self::row("iface", "WireGuard interface available", false,
                "no active tunnel".into()),
        });
        out.push(self.handshake_check(active.as_deref()).await);
        let net = crate::netcheck::internet_ok().await;
        out.push(Self::row("internet", "Internet connectivity", net,
            if net { "reachable".into() } else { "unreachable".into() }));
        out
    }
}
