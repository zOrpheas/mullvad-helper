// Render configs list + deps + doctor rows.
use crate::state::{Busy, Job, Snapshot};
use crate::worker::WorkerHandle;
use gtk4::prelude::*;
use libadwaita::prelude::*;

pub fn render(v: &super::ConfigsView, s: &Snapshot, worker: &WorkerHandle) {
    while let Some(c) = v.cfg_list.first_child() {
        v.cfg_list.remove(&c);
    }
    if s.configs.is_empty() {
        let row = libadwaita::ActionRow::new();
        row.set_title("No servers yet");
        row.set_subtitle("Use the + button on the main screen to import a Mullvad .conf file.");
        v.cfg_list.append(&row);
    }
    for cfg in &s.configs {
        let row = libadwaita::ExpanderRow::new();
        row.set_title(&format!("{} {}", if cfg.active { "●" } else { "○" }, cfg.display));
        row.set_subtitle(&cfg.name);
        let toggle = gtk4::Button::with_label(if cfg.active { "Disconnect" } else { "Connect" });
        if cfg.active {
            toggle.add_css_class("destructive-action");
        } else {
            toggle.add_css_class("suggested-action");
        }
        row.add_prefix(&toggle);
        let w = worker.clone();
        let name = cfg.name.clone();
        let active = cfg.active;
        toggle.connect_clicked(move |_| {
            if active {
                w.send(Job::Disconnect(name.clone()));
            } else {
                w.send(Job::Connect(name.clone()));
            }
        });
        // Details row: autostart switch + delete button.
        let detail = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
        detail.set_margin_top(6);
        detail.set_margin_bottom(6);
        let auto_label = gtk4::Label::new(Some("Start on boot"));
        auto_label.set_hexpand(true);
        auto_label.set_xalign(0.0);
        let switch = gtk4::Switch::new();
        switch.set_active(cfg.autostart);
        switch.set_sensitive(!matches!(s.busy, Busy::Working(_)));
        let w2 = worker.clone();
        let name2 = cfg.name.clone();
        switch.connect_state_set(move |_, state| {
            w2.send(Job::SetAutostart { name: name2.clone(), enabled: state });
            glib::Propagation::Proceed
        });
        let del = gtk4::Button::with_label("Delete");
        del.add_css_class("destructive-action");
        let w3 = worker.clone();
        let name3 = cfg.name.clone();
        let active3 = cfg.active;
        del.connect_clicked(move |_| {
            if active3 {
                w3.send(Job::Disconnect(name3.clone()));
            }
            w3.send(Job::Delete(name3.clone()));
        });
        detail.append(&auto_label);
        detail.append(&switch);
        detail.append(&del);
        let detail_row = libadwaita::ActionRow::new();
        detail_row.set_child(Some(&detail));
        row.add_row(&detail_row);
        v.cfg_list.append(&row);
    }
    while let Some(c) = v.deps_box.first_child() {
        v.deps_box.remove(&c);
    }
    if s.deps.is_empty() {
        let l = gtk4::Label::new(Some("Loading…"));
        l.add_css_class("dim-label");
        v.deps_box.append(&l);
    }
    for d in &s.deps {
        let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        let mark = gtk4::Label::new(Some(if d.present { "✓" } else { "✗" }));
        mark.add_css_class(if d.present { "td-check-ok" } else { "td-check-bad" });
        let label = gtk4::Label::new(Some(&format!("{} — {}", d.label, d.detail)));
        label.set_hexpand(true);
        label.set_xalign(0.0);
        label.set_wrap(true);
        row.append(&mark);
        row.append(&label);
        v.deps_box.append(&row);
    }
    v.install_btn.set_visible(!s.missing_packages.is_empty());
    while let Some(c) = v.doctor_list.first_child() {
        v.doctor_list.remove(&c);
    }
    if s.doctor.is_empty() {
        let row = libadwaita::ActionRow::new();
        row.set_title("Press Troubleshoot on the main screen to run a full check");
        v.doctor_list.append(&row);
    }
    for d in &s.doctor {
        let row = libadwaita::ActionRow::new();
        row.set_title(&format!("{} {}", if d.ok { "✓" } else { "✗" }, d.label));
        row.set_subtitle(&d.message);
        v.doctor_list.append(&row);
    }
}
