// Servers, troubleshooting & settings page.
mod render;
mod wire;

pub use render::render;
pub use wire::wire;

use gtk4::prelude::*;
use libadwaita::prelude::*;

pub struct ConfigsView {
    pub page: gtk4::ScrolledWindow,
    pub cfg_list: gtk4::ListBox,
    pub deps_box: gtk4::Box,
    pub doctor_list: gtk4::ListBox,
    pub install_btn: gtk4::Button,
    pub repair_btn: gtk4::Button,
    pub on_top: libadwaita::SwitchRow,
}

pub fn build() -> ConfigsView {
    let scroll = gtk4::ScrolledWindow::new();
    scroll.set_vexpand(true);
    let main = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    main.set_margin_top(16);
    main.set_margin_bottom(16);
    main.set_margin_start(16);
    main.set_margin_end(16);
    let title = gtk4::Label::new(Some("Servers"));
    title.add_css_class("title-2");
    title.set_xalign(0.0);
    main.append(&title);
    let cfg_list = gtk4::ListBox::new();
    cfg_list.add_css_class("boxed-list");
    cfg_list.set_selection_mode(gtk4::SelectionMode::None);
    main.append(&cfg_list);
    let deps_title = gtk4::Label::new(Some("Required software"));
    deps_title.add_css_class("title-3");
    deps_title.set_xalign(0.0);
    main.append(&deps_title);
    let deps_box = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    let deps_row = libadwaita::ActionRow::new();
    deps_row.set_child(Some(&deps_box));
    main.append(&deps_row);
    let install_btn = gtk4::Button::with_label("Install missing packages");
    install_btn.set_visible(false);
    main.append(&install_btn);
    let repair_btn = gtk4::Button::with_label("Repair permissions");
    main.append(&repair_btn);
    let doc_title = gtk4::Label::new(Some("Troubleshooting"));
    doc_title.add_css_class("title-3");
    doc_title.set_xalign(0.0);
    main.append(&doc_title);
    let doctor_list = gtk4::ListBox::new();
    doctor_list.add_css_class("boxed-list");
    doctor_list.set_selection_mode(gtk4::SelectionMode::None);
    main.append(&doctor_list);
    let settings_title = gtk4::Label::new(Some("Settings"));
    settings_title.add_css_class("title-3");
    settings_title.set_xalign(0.0);
    main.append(&settings_title);
    let settings_list = gtk4::ListBox::new();
    settings_list.add_css_class("boxed-list");
    settings_list.set_selection_mode(gtk4::SelectionMode::None);
    let on_top = libadwaita::SwitchRow::new();
    on_top.set_title("Keep window on top");
    on_top.set_subtitle("Stay above other windows, on every workspace");
    settings_list.append(&on_top);
    main.append(&settings_list);
    scroll.set_child(Some(&main));
    ConfigsView { page: scroll, cfg_list, deps_box, doctor_list, install_btn, repair_btn, on_top }
}
