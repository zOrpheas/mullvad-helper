// Mullvad Helper GUI: native GTK4 + libadwaita.
mod app;
mod hyprland;
mod settings;
mod state;
mod tray;
mod view_configs;
mod view_main;
mod worker;

use gtk4::gio::prelude::{ApplicationExt, ApplicationExtManual};

fn main() {
    mullvad_helper_core::logging::init_logging();
    let app = libadwaita::Application::builder()
        .application_id("io.github.mullvadhelper.MullvadHelper")
        .build();
    app.connect_activate(crate::app::build_ui);
    app.run();
}


