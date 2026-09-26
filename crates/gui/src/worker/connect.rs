// Connect / disconnect / toggle / check-ip.
use crate::worker::Worker;

impl Worker {
    pub(crate) async fn toggle(&mut self) {
        if let Some(a) = self.snap.active_iface.clone() {
            self.disconnect(&a).await;
        } else if let Some(s) = self.snap.selected.clone() {
            self.connect(&s).await;
        } else if let Some(f) = self.snap.configs.first().map(|c| c.name.clone()) {
            self.connect(&f).await;
        } else {
            self.info("Import a .conf first.".to_string());
        }
    }
    pub(crate) async fn connect(&mut self, name: &str) {
        self.busy("Connecting…");
        let wg = mullvad_helper_backend::wireguard::WireGuardService::new(
            self.be.runner.clone(),
            self.be.privs.clone(),
        );
        match wg.connect(name).await {
            Ok(_) => {
                self.snap.selected = Some(name.to_string());
                for _ in 0..6 {
                    self.refresh(false).await;
                    let fresh = self
                        .snap
                        .status
                        .as_ref()
                        .and_then(|s| s.latest_handshake_secs_ago)
                        .map(|a| a <= 180)
                        .unwrap_or(false);
                    if fresh {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                }
                self.idle();
                self.info(format!("Connected to {name}. Verifying…"));
                self.check_ip().await;
            }
            Err(e) => {
                self.idle();
                self.err(e.human(), Some(e.technical()));
                self.refresh(false).await;
            }
        }
    }
    pub(crate) async fn disconnect(&mut self, name: &str) {
        self.busy("Disconnecting…");
        let wg = mullvad_helper_backend::wireguard::WireGuardService::new(
            self.be.runner.clone(),
            self.be.privs.clone(),
        );
        match wg.disconnect(name).await {
            Ok(_) => {
                self.idle();
                self.info(format!("Disconnected {name}."));
                self.refresh(false).await;
            }
            Err(e) => {
                self.idle();
                self.err(e.human(), Some(e.technical()));
                self.refresh(false).await;
            }
        }
    }
    pub(crate) async fn check_ip(&mut self) {
        self.busy("Checking IP…");
        match mullvad_helper_backend::netcheck::public_ip("").await {
            Ok(ip) => {
                let text = match (&ip.country, &ip.city, ip.mullvad_exit) {
                    (Some(c), Some(city), Some(true)) => {
                        format!("Public IP {} — exit in {city}, {c}", ip.ip)
                    }
                    _ => format!("Public IP {}", ip.ip),
                };
                self.snap.ip = Some(ip);
                self.snap.internet_ok = Some(true);
                self.ip_at = Some(std::time::Instant::now());
                self.idle();
                self.info(text);
            }
            Err(e) => {
                self.snap.internet_ok = Some(false);
                self.idle();
                self.err(
                    "Could not reach the IP check service.".to_string(),
                    Some(format!("{e:#}")),
                );
            }
        }
        self.refresh(false).await;
    }
}
