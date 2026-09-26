// Hyprland tiles every window and Wayland gives apps no "keep above" API, so
// talk to the compositor directly. Everything here is a no-op elsewhere.
use std::process::Command;

const CLASS: &str = "io.github.mullvadhelper.MullvadHelper";

pub fn active() -> bool {
    std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some()
}

/// Open small, floating and centered instead of tiled full-size.
pub fn float_window() {
    if active() {
        let class = CLASS.replace('.', r"\.");
        hyprctl(&["keyword", "windowrule", &format!("match:class ^({class})$, float on, size 400 600, center on")]);
    }
}

/// Pin (on top, on every workspace) or unpin our window. `pin` toggles, so
/// only dispatch when the current state differs.
pub fn set_on_top(on: bool) {
    if !active() {
        return;
    }
    let Some(out) = hyprctl(&["clients", "-j"]) else { return };
    let Ok(clients) = serde_json::from_str::<Vec<serde_json::Value>>(&out) else { return };
    for c in clients.iter().filter(|c| c["class"] == CLASS) {
        if let (Some(pinned), Some(addr)) = (c["pinned"].as_bool(), c["address"].as_str()) {
            if pinned != on {
                hyprctl(&["dispatch", "pin", &format!("address:{addr}")]);
            }
        }
    }
}

fn hyprctl(args: &[&str]) -> Option<String> {
    let out = Command::new("hyprctl").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}
