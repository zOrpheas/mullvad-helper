//! Config store: import/validate/stage/install/list/rename/delete.
//! Reads of /etc/wireguard happen unprivileged; writes go via helper.
use crate::command::CommandRunner;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ConfigStore<R: CommandRunner> {
    runner: Arc<R>,
    privileged: Arc<crate::privilege::PrivilegeService<R>>,
}

impl<R: CommandRunner> ConfigStore<R> {
    pub fn new(runner: Arc<R>, privileged: Arc<crate::privilege::PrivilegeService<R>>) -> Self {
        Self { runner, privileged }
    }
    /// Validate file contents; returns safe metadata (no keys).
    pub fn validate_import(
        &self,
        file_name: &str,
        contents: &str,
    ) -> Result<mullvad_helper_core::SafeConfigMetadata, mullvad_helper_core::WireGuardParseError> {
        let stem = file_name.rsplit('/').next().unwrap_or(file_name);
        let stem = stem.strip_suffix(".conf").unwrap_or(stem);
        mullvad_helper_core::parser::validate_tunnel_name(stem)?;
        Ok(mullvad_helper_core::parser::parse_wireguard_config(contents, stem)?.metadata)
    }
    /// List installed tunnels + active interfaces.
    ///
    /// Names come from the privileged helper because /etc/wireguard is 0700
    /// root-only (we enforce that ourselves) — an unprivileged `ls` just fails.
    /// Liveness comes from `wg show interfaces`, which DOES work without
    /// privileges, so a running tunnel is never reported as "not running".
    pub async fn list(&self) -> Vec<mullvad_helper_core::ManagedConfig> {
        let mut names: Vec<String> = vec![];
        if let Ok(o) = self.privileged.list_configs().await {
            if o.success() {
                for line in o.stdout.lines() {
                    let n = line.trim();
                    if mullvad_helper_core::parser::validate_tunnel_name(n).is_ok() {
                        names.push(n.to_string());
                    }
                }
            }
        }
        // Interfaces that are up right now (unprivileged query).
        let mut active_names: Vec<String> = vec![];
        if let Ok(o) = self.runner.run("wg", &["show", "interfaces"]).await {
            if o.success() {
                for iface in o.stdout.split_whitespace() {
                    if mullvad_helper_core::parser::validate_tunnel_name(iface).is_ok() {
                        active_names.push(iface.to_string());
                    }
                }
            }
        }
        for iface in &active_names {
            if !names.contains(iface) {
                names.push(iface.clone());
            }
        }
        names.sort();
        names.dedup();
        let mut out = vec![];
        for n in names {
            let active = active_names.contains(&n);
            let autostart = self.autostart(&n).await;
            // Friendly metadata cached at import time (contains no keys).
            let metadata = mullvad_helper_core::metadata_cache::get(&n)
                .unwrap_or_else(|| mullvad_helper_core::SafeConfigMetadata {
                    name: n.clone(),
                    display_name: mullvad_helper_core::parser::prettify_tunnel_name(&n),
                    endpoint_host: String::new(),
                    endpoint_port: 0,
                    addresses: vec![],
                    dns: vec![],
                    allowed_ips: vec![],
                    kill_switch_detected: false,
                    hook_commands: vec![],
                    hooks_look_risky: false,
                    provider_hint: None,
                });
            out.push(mullvad_helper_core::ManagedConfig {
                metadata,
                installed_path: Some(format!("/etc/wireguard/{n}.conf")),
                autostart_enabled: autostart,
                active,
            });
        }
        out
    }

    /// Persist SAFE metadata for a freshly imported config so the UI can show
    /// endpoint/city without ever reading /etc/wireguard back.
    pub fn remember(&self, meta: &mullvad_helper_core::SafeConfigMetadata) {
        mullvad_helper_core::metadata_cache::store(meta);
    }

    /// Forget metadata for a deleted config.
    pub fn forget(&self, name: &str) {
        mullvad_helper_core::metadata_cache::forget(name);
    }

    async fn autostart(&self, name: &str) -> bool {
        let unit = format!("wg-quick@{name}.service");
        if let Ok(o) = self.runner.run("systemctl", &["is-enabled", &unit]).await {
            return o.success() && o.stdout.trim() == "enabled";
        }
        false
    }
    /// Install: caller stages contents to a temp file, helper copies 0600.
    pub async fn install_staged(&self, staging_path: &str, name: &str) -> Result<String, anyhow::Error> {
        mullvad_helper_core::parser::validate_tunnel_name(name)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let out = self.privileged.install_config(staging_path, name).await?;
        if out.success() {
            Ok(out.stdout)
        } else {
            anyhow::bail!("{}", out.stderr.trim())
        }
    }

    /// Delete an installed config via the privileged helper.
    pub async fn delete(&self, name: &str) -> Result<String, anyhow::Error> {
        mullvad_helper_core::parser::validate_tunnel_name(name)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let out = self.privileged.remove_config(name).await?;
        if out.success() {
            mullvad_helper_core::metadata_cache::forget(name);
            Ok(out.stdout)
        } else {
            anyhow::bail!("{}", out.stderr.trim())
        }
    }

    /// Rename = copy bytes (privileged read impossible) — caller must supply
    /// the source bytes. We stage them and install under the new name, then
    /// delete the old config. Used for user-owned imports and renames.
    pub async fn rename_via_bytes(
        &self,
        old: &str,
        new: &str,
        source_bytes: &[u8],
        staging_path: &str,
    ) -> Result<(), anyhow::Error> {
        mullvad_helper_core::parser::validate_tunnel_name(new)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        std::fs::write(staging_path, source_bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(staging_path, std::fs::Permissions::from_mode(0o600))?;
        }
        self.install_staged(staging_path, new).await?;
        let _ = std::fs::remove_file(staging_path);
        // Best-effort cleanup of the old file; surface errors but don't fail
        // the rename if the new config is already in place.
        let _ = self.delete(old).await;
        Ok(())
    }
}
