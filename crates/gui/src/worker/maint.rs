//! Import / autostart / delete.
use crate::worker::Worker;

impl Worker {
    pub(crate) async fn import(&mut self, path: &std::path::Path) {
        self.busy("Importing…");
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) => {
                self.idle();
                self.err("Could not read file.".to_string(), Some(format!("{e:#}")));
                return;
            }
        };
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("tunnel.conf");
        let store = mullvad_helper_backend::configs::ConfigStore::new(
            self.be.runner.clone(), self.be.privs.clone());
        let meta = match store.validate_import(fname, &raw) {
            Ok(m) => m,
            Err(e) => {
                self.idle();
                self.err(format!("Not a WireGuard config: {e}"), None);
                return;
            }
        };
        if meta.hooks_look_risky {
            self.idle();
            self.err(format!("Refuses install: runs shell as root."), None);
            return;
        }
        let staging = format!("/tmp/mullvad-helper-{}.conf", meta.name);
        if std::fs::write(&staging, &raw).is_err() {
            self.idle();
            self.err("Could not stage config.".to_string(), None);
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &staging, std::fs::Permissions::from_mode(0o600));
        }
        match store.install_staged(&staging, &meta.name).await {
            Ok(_) => {
                let _ = std::fs::remove_file(&staging);
                store.remember(&meta);
                self.snap.selected = Some(meta.name.clone());
                self.idle();
                self.info(format!("Installed {}.", meta.display_name));
                self.refresh(true).await;
            }
            Err(e) => {
                let _ = std::fs::remove_file(&staging);
                self.idle();
                self.err("Needs admin approval.".to_string(), Some(format!("{e:#}")));
                self.refresh(true).await;
            }
        }
    }

    pub(crate) async fn autostart(&mut self, name: &str, enabled: bool) {
        self.busy(if enabled { "Enabling…" } else { "Disabling…" });
        let sysd = mullvad_helper_backend::systemd::SystemdService::new(
            self.be.runner.clone(), self.be.privs.clone());
        match sysd.set_enabled(name, enabled).await {
            Ok(_) => {
                self.idle();
                self.info(format!("Startup updated for {name}."));
                self.refresh(false).await;
            }
            Err(e) => {
                self.idle();
                self.err("Could not change startup.".to_string(), Some(format!("{e:#}")));
            }
        }
    }
    pub(crate) async fn delete(&mut self, name: &str) {
        self.busy("Deleting…");
        let store = mullvad_helper_backend::configs::ConfigStore::new(
            self.be.runner.clone(), self.be.privs.clone());
        match store.delete(name).await {
            Ok(_) => {
                if self.snap.selected.as_deref() == Some(name) {
                    self.snap.selected = None;
                }
                self.idle();
                self.info(format!("Deleted {name}."));
                self.refresh(true).await;
            }
            Err(e) => {
                self.idle();
                self.err("Could not delete.".to_string(), Some(format!("{e:#}")));
            }
        }
    }
    pub(crate) async fn repair(&mut self) {
        self.busy("Repairing…");
        match self.be.privs.repair_perms().await {
            Ok(o) if o.status == 0 => {
                self.idle();
                self.info("Permissions repaired.".to_string());
                self.refresh(true).await;
            }
            Ok(o) => {
                self.idle();
                self.err("Repair rejected.".to_string(), Some(o.stderr));
            }
            Err(e) => {
                self.idle();
                self.err("Needs admin approval.".to_string(), Some(e.to_string()));
            }
        }
    }
    pub(crate) async fn install(&mut self, pkgs: &[String]) {
        if pkgs.is_empty() {
            return;
        }
        self.busy("Installing…");
        match self.be.privs.install_packages(pkgs).await {
            Ok(o) if o.status == 0 => {
                self.idle();
                self.info(format!("Installed {}.", pkgs.join(", ")));
                self.refresh(true).await;
            }
            Ok(o) => {
                self.idle();
                self.err("Install failed.".to_string(), Some(o.stderr));
            }
            Err(e) => {
                self.idle();
                self.err("Needs admin approval.".to_string(), Some(e.to_string()));
            }
        }
    }
    pub(crate) async fn dns_fix(&mut self) {
        self.busy("Fixing DNS…");
        let pkgs = vec!["systemd-resolvconf".to_string()];
        match self.be.privs.install_packages(&pkgs).await {
            Ok(o) if o.status == 0 => {
                self.idle();
                self.info("Installed systemd-resolvconf. Reconnect.".to_string());
                self.refresh(true).await;
            }
            Ok(o) => {
                self.idle();
                self.err("DNS fix failed.".to_string(), Some(o.stderr));
            }
            Err(e) => {
                self.idle();
                self.err("Needs admin approval.".to_string(), Some(e.to_string()));
            }
        }
    }
}
