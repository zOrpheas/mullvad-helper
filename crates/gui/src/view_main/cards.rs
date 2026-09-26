// Server picker first; technical details tucked into collapsed rows.
use gtk4::prelude::*;
use libadwaita::prelude::*;

pub fn append_cards(v: &super::MainView) {
    let server = libadwaita::PreferencesGroup::new();
    let cfg_row = libadwaita::ActionRow::new();
    cfg_row.set_title("Server");
    v.cfg_combo.set_valign(gtk4::Align::Center);
    cfg_row.add_suffix(&v.cfg_combo);
    v.import_btn.set_tooltip_text(Some("Import a Mullvad server file (.conf)"));
    v.import_btn.add_css_class("flat");
    v.import_btn.set_valign(gtk4::Align::Center);
    cfg_row.add_suffix(&v.import_btn);
    server.add(&cfg_row);
    v.col.append(&server);

    let details = libadwaita::PreferencesGroup::new();
    let conn = libadwaita::ExpanderRow::new();
    conn.set_title("Connection details");
    v.checks_box.set_margin_top(8);
    v.checks_box.set_margin_bottom(8);
    v.checks_box.set_margin_start(12);
    let checks_row = libadwaita::ActionRow::new();
    checks_row.set_child(Some(&v.checks_box));
    conn.add_row(&checks_row);
    for (title, value) in [
        ("Public IP", &v.ip_value),
        ("Last contact with server", &v.hs_value),
        ("Data used", &v.traffic_value),
    ] {
        value.add_css_class("dim-label");
        let row = libadwaita::ActionRow::new();
        row.set_title(title);
        row.add_suffix(value);
        conn.add_row(&row);
    }
    details.add(&conn);
    let dns_row = libadwaita::ExpanderRow::new();
    dns_row.set_title("DNS");
    v.dns_value.add_css_class("dim-label");
    dns_row.add_suffix(&v.dns_value);
    v.dns_detail.set_wrap(true);
    v.dns_detail.set_xalign(0.0);
    v.dns_detail.set_selectable(true);
    v.dns_detail.set_margin_top(8);
    v.dns_detail.set_margin_bottom(8);
    v.dns_detail.set_margin_start(12);
    let drow = libadwaita::ActionRow::new();
    drow.set_child(Some(&v.dns_detail));
    dns_row.add_row(&drow);
    v.dns_fix_btn.set_visible(false);
    v.dns_fix_btn.set_valign(gtk4::Align::Center);
    v.dns_fix_btn.add_css_class("suggested-action");
    dns_row.add_suffix(&v.dns_fix_btn);
    details.add(&dns_row);
    v.col.append(&details);

    let actions = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    actions.set_halign(gtk4::Align::Center);
    v.ip_btn.add_css_class("pill");
    v.doctor_btn.add_css_class("pill");
    actions.append(&v.ip_btn);
    actions.append(&v.doctor_btn);
    v.col.append(&actions);
}
