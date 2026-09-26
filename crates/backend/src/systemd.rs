//! systemd backend: wg-quick@<name>.service enable/disable/status.

use crate::command::CommandRunner;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SystemdService<R: CommandRunner> {
    runner: Arc<R>,
    privileged: Arc<crate::privilege::PrivilegeService<R>>,
}

impl<R: CommandRunner> SystemdService<R> {
    pub fn new(runner: Arc<R>, privileged: Arc<crate::privilege::PrivilegeService<R>>) -> Self {
        Self { runner, privileged }
    }

    pub fn unit_for(name: &str) -> String {
        format!("wg-quick@{name}.service")
    }

    pub async fn is_enabled(&self, name: &str) -> bool {
        let unit = Self::unit_for(name);
        if let Ok(o) = self
            .runner
            .run("systemctl", &["is-enabled", &unit])
            .await
        {
            return o.success() && o.stdout.trim() == "enabled";
        }
        false
    }

    pub async fn is_active(&self, name: &str) -> bool {
        let unit = Self::unit_for(name);
        if let Ok(o) = self.runner.run("systemctl", &["is-active", &unit]).await {
            return o.success() && o.stdout.trim() == "active";
        }
        false
    }

    pub async fn set_enabled(
        &self,
        name: &str,
        enabled: bool,
    ) -> Result<String, anyhow::Error> {
        let out = if enabled {
            self.privileged.systemctl_enable(&Self::unit_for(name)).await?
        } else {
            self.privileged.systemctl_disable(&Self::unit_for(name)).await?
        };
        if out.success() {
            Ok(out.stdout)
        } else {
            anyhow::bail!("systemctl failed: {}", out.stderr.trim())
        }
    }
}
