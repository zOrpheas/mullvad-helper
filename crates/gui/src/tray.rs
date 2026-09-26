// Tray icon (StatusNotifierItem, shown by Waybar's `tray` module). Passive,
// i.e. hidden, while the window is open; appears when running in background.
use crate::state::UiMsg;
use ksni::menu::StandardItem;

pub struct Tray {
    pub tx: async_channel::Sender<UiMsg>,
    pub window_visible: bool,
    pub connected: bool,
    pub status: &'static str,
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "mullvad-helper".into()
    }
    fn title(&self) -> String {
        "Mullvad Helper".into()
    }
    fn category(&self) -> ksni::Category {
        ksni::Category::ApplicationStatus
    }
    fn status(&self) -> ksni::Status {
        if self.window_visible {
            ksni::Status::Passive
        } else {
            ksni::Status::Active
        }
    }
    fn icon_name(&self) -> String {
        if self.connected { "network-vpn-symbolic" } else { "network-vpn-disconnected-symbolic" }.into()
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: format!("Mullvad Helper: {}", self.status),
            ..Default::default()
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send_blocking(UiMsg::Show);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Open".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.tx.send_blocking(UiMsg::Show);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Disconnect and quit".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.tx.send_blocking(UiMsg::Kill);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}
