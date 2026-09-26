// Main view build: hero + banner + placeholders; cards appended after.
use gtk4::prelude::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

pub fn build() -> super::MainView {
    let scroll = gtk4::ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);
    let col = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    col.set_margin_top(16);
    col.set_margin_bottom(16);
    col.set_margin_start(16);
    col.set_margin_end(16);
    let hero = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    hero.add_css_class("td-hero");
    hero.add_css_class("td-hero-off");
    let dot = gtk4::Image::from_icon_name("network-vpn-disconnected-symbolic");
    dot.set_pixel_size(64);
    dot.add_css_class("td-status-off");
    let title = gtk4::Label::new(Some("Not protected"));
    title.add_css_class("td-big");
    let subtitle = gtk4::Label::new(Some("Import a Mullvad server file to begin"));
    subtitle.add_css_class("dim-label");
    subtitle.set_wrap(true);
    subtitle.set_justify(gtk4::Justification::Center);
    hero.append(&dot);
    hero.append(&title);
    hero.append(&subtitle);
    let busy_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    let spinner = gtk4::Spinner::new();
    let busy_label = gtk4::Label::new(None);
    busy_label.add_css_class("dim-label");
    busy_row.set_halign(gtk4::Align::Center);
    busy_row.append(&spinner);
    busy_row.append(&busy_label);
    busy_row.set_visible(false);
    hero.append(&busy_row);
    let primary_btn = gtk4::Button::with_label("Connect");
    primary_btn.add_css_class("suggested-action");
    primary_btn.add_css_class("pill");
    primary_btn.add_css_class("td-primary");
    primary_btn.set_halign(gtk4::Align::Center);
    primary_btn.set_margin_top(8);
    hero.append(&primary_btn);
    col.append(&hero);
    let banner = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    banner.set_visible(false);
    let banner_label = gtk4::Label::new(None);
    banner_label.set_wrap(true);
    banner_label.set_xalign(0.0);
    banner_label.set_selectable(true);
    let tech_expander = gtk4::Expander::new(Some("Technical details"));
    tech_expander.set_visible(false);
    let tech_label = gtk4::Label::new(None);
    tech_label.set_wrap(true);
    tech_label.set_xalign(0.0);
    tech_label.set_selectable(true);
    tech_label.add_css_class("td-tech");
    tech_expander.set_child(Some(&tech_label));
    let banner_dismiss = gtk4::Button::with_label("Dismiss");
    banner.append(&banner_label);
    banner.append(&tech_expander);
    banner.append(&banner_dismiss);
    col.append(&banner);
    scroll.set_child(Some(&col));
    let v = super::MainView {
        page: scroll,
        col,
        hero,
        dot,
        title,
        subtitle,
        busy_row,
        spinner,
        busy_label,
        primary_btn,
        banner,
        banner_label,
        tech_expander,
        tech_label,
        banner_dismiss,
        checks_box: gtk4::Box::new(gtk4::Orientation::Vertical, 4),
        ip_value: gtk4::Label::new(None),
        hs_value: gtk4::Label::new(None),
        traffic_value: gtk4::Label::new(None),
        dns_value: gtk4::Label::new(None),
        dns_detail: gtk4::Label::new(None),
        dns_fix_btn: gtk4::Button::with_label("Fix DNS"),
        cfg_combo: gtk4::DropDown::from_strings(&[""]),
        cfg_names: Rc::new(RefCell::new(Vec::new())),
        combo_guard: Rc::new(Cell::new(false)),
        import_btn: gtk4::Button::from_icon_name("list-add-symbolic"),
        ip_btn: gtk4::Button::with_label("Check my IP"),
        doctor_btn: gtk4::Button::with_label("Troubleshoot"),
    };
    super::cards::append_cards(&v);
    v
}
