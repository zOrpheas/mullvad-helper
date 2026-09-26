// Worker helpers: emit/notice/handle-dispatch.
use crate::state::{Notice, UiMsg};
use std::time::Instant;

impl super::Worker {
    pub(crate) fn emit(&self) {
        let _ = self.tx.try_send(UiMsg::Snap(self.snap.clone()));
    }
    pub(crate) fn busy(&mut self, label: &'static str) {
        self.snap.busy = crate::state::Busy::Working(label);
        self.emit();
    }
    pub(crate) fn idle(&mut self) {
        self.snap.busy = crate::state::Busy::Idle;
        self.emit();
    }
    pub(crate) fn info(&mut self, text: String) {
        mullvad_helper_core::logging::append_log_line(&format!("INFO  {text}"));
        self.snap.notice = Some(Notice {
            error: false,
            text,
            technical: None,
            at: Instant::now(),
        });
        self.emit();
    }
    pub(crate) fn err(&mut self, text: String, technical: Option<String>) {
        let tech = technical.map(|t| mullvad_helper_core::redact::redact_secrets(&t));
        mullvad_helper_core::logging::append_log_line(&format!(
            "ERROR {text}{}",
            match &tech {
                Some(t) => format!(" | {t}"),
                None => String::new(),
            }
        ));
        self.snap.notice = Some(Notice {
            error: true,
            text,
            technical: tech,
            at: Instant::now(),
        });
        self.emit();
    }
    pub(crate) async fn handle(&mut self, job: crate::state::Job) {
        use crate::state::Job as J;
        match job {
            J::Refresh => self.refresh(false).await,
            J::RefreshFull => self.refresh(true).await,
            J::Select(n) => {
                self.snap.selected = Some(n);
                self.emit();
            }
            J::ToggleSelected => self.toggle().await,
            J::Connect(n) => self.connect(&n).await,
            J::Disconnect(n) => self.disconnect(&n).await,
            J::Import(p) => self.import(&p).await,
            J::CheckIp => self.check_ip().await,
            J::Doctor => {
                self.want_doctor = true;
                self.refresh(true).await;
            }
            J::InstallMissing => {
                let pkgs = self.snap.missing_packages.clone();
                self.install(&pkgs).await;
            }
            J::SetAutostart { name, enabled } => self.autostart(&name, enabled).await,
            J::Delete(n) => self.delete(&n).await,
            J::RepairPerms => self.repair().await,
            J::ApplyDnsFix => self.dns_fix().await,
            J::DismissNotice => {
                self.snap.notice = None;
                self.emit();
            }
            J::Quit => {
                if let Some(iface) = self.snap.active_iface.clone() {
                    self.disconnect(&iface).await;
                }
                // Disconnect failed (e.g. password refused): stay open so the
                // error is visible instead of silently leaving the VPN up.
                if self.snap.active_iface.is_none() {
                    let _ = self.tx.send(UiMsg::Quit).await;
                }
            }
        }
    }
    pub(crate) async fn refresh(&mut self, full: bool) {
        super::refresh::refresh_inner(self, full).await;
    }
}

