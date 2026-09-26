// Render the main view (hero, banner, details) from a snapshot.
use crate::state::{Health, Snapshot, ago};
use gtk4::prelude::*;

pub fn render(v: &super::MainView, s: &Snapshot) {
    render_hero(v, s);
    render_details(v, s);
}

fn render_hero(v: &super::MainView, s: &Snapshot) {
    let health = s.health;
    let title = health.label();
    let icon = match health {
        Health::Disconnected => "network-vpn-disconnected-symbolic",
        Health::Waiting => "network-vpn-acquiring-symbolic",
        Health::Degraded => "network-vpn-no-route-symbolic",
        Health::Connected => "network-vpn-symbolic",
    };
    v.dot.set_icon_name(Some(icon));
    v.title.set_text(title);
    for c in ["td-status-ok", "td-status-wait", "td-status-warn", "td-status-off"] {
        v.dot.remove_css_class(c);
    }
    v.dot.add_css_class(match health {
        Health::Connected => "td-status-ok",
        Health::Waiting => "td-status-wait",
        Health::Degraded => "td-status-warn",
        Health::Disconnected => "td-status-off",
    });
    for c in ["td-hero-ok", "td-hero-wait", "td-hero-off"] {
        v.hero.remove_css_class(c);
    }
    v.hero.add_css_class(match health {
        Health::Connected => "td-hero-ok",
        Health::Waiting | Health::Degraded => "td-hero-wait",
        Health::Disconnected => "td-hero-off",
    });
    let place = s.ip.as_ref().and_then(|ip| match (&ip.city, &ip.country) {
        (Some(city), Some(c)) => Some(format!("{city}, {c}")),
        _ => None,
    });
    let subtitle = match (&s.active_iface, place, s.configs.len()) {
        (Some(_), Some(p), _) if health == Health::Connected => format!("Your traffic appears to come from {p}"),
        (Some(i), _, _) => format!("Using server {i}"),
        (None, _, 0) => "Import a Mullvad server file to begin".to_string(),
        (None, _, _) => "Press Connect to hide your IP".to_string(),
    };
    v.subtitle.set_text(&subtitle);
    let busy = s.busy.label();
    v.busy_row.set_visible(busy.is_some());
    v.spinner.set_spinning(busy.is_some());
    v.busy_label.set_text(busy.unwrap_or(""));
    v.primary_btn.set_sensitive(busy.is_none());
    if s.active_iface.is_some() {
        v.primary_btn.set_label("Disconnect");
        v.primary_btn.remove_css_class("suggested-action");
        v.primary_btn.add_css_class("destructive-action");
    } else {
        v.primary_btn.set_label("Connect");
        v.primary_btn.remove_css_class("destructive-action");
        v.primary_btn.add_css_class("suggested-action");
    }
    match &s.notice {
        Some(n) => {
            v.banner.set_visible(true);
            v.banner.remove_css_class("td-banner-err");
            v.banner.remove_css_class("td-banner-info");
            if n.error {
                v.banner.add_css_class("td-banner-err");
            } else {
                v.banner.add_css_class("td-banner-info");
            }
            v.banner_label.set_text(&n.text);
            match &n.technical {
                Some(t) => {
                    v.tech_expander.set_visible(true);
                    v.tech_label.set_text(t);
                }
                None => {
                    v.tech_expander.set_visible(false);
                    v.tech_label.set_text("");
                }
            }
        }
        None => v.banner.set_visible(false),
    }
}


fn render_details(v: &super::MainView, s: &Snapshot) {
    let hs = s
        .status
        .as_ref()
        .and_then(|st| st.latest_handshake_secs_ago)
        .map(|a| format!("{} ago", ago(a)))
        .unwrap_or_else(|| "—".to_string());
    v.hs_value.set_text(&hs);
    let traffic = s
        .status
        .as_ref()
        .map(|st| format!("↓ {}  ↑ {}", fmt_bytes(st.rx_bytes), fmt_bytes(st.tx_bytes)))
        .unwrap_or_else(|| "—".to_string());
    v.traffic_value.set_text(&traffic);
    clear_box(&v.checks_box);
    if s.active_iface.is_some() {
        let st = s.status.as_ref();
        let iface_ok = st.map(|x| x.interface_exists).unwrap_or(false);
        let hs_ok = st
            .and_then(|x| x.latest_handshake_secs_ago)
            .map(|a| a <= 180)
            .unwrap_or(false);
        add_check(&v.checks_box, "Tunnel is up", iface_ok);
        add_check(&v.checks_box, "Server is answering", hs_ok);
        match s.internet_ok {
            Some(true) => add_check(&v.checks_box, "Internet works", true),
            Some(false) => add_check(&v.checks_box, "Internet works", false),
            None => add_pending(&v.checks_box, "Internet — press Check my IP"),
        }
        if s.ip.is_some() {
            add_check(&v.checks_box, "IP is hidden", true);
        } else {
            add_pending(&v.checks_box, "VPN IP — press Check my IP");
        }
    } else {
        add_pending(&v.checks_box, "Connect to see tunnel health");
    }
    match &s.ip {
        Some(ip) => {
            let extra = match (&ip.city, &ip.country) {
                (Some(city), Some(c)) => format!("{city}, {c}"),
                _ => String::new(),
            };
            if extra.is_empty() {
                v.ip_value.set_text(&ip.ip);
            } else {
                v.ip_value.set_text(&format!("{} ({extra})", ip.ip));
            }
        }
        None => v.ip_value.set_text("Not checked yet"),
    }
    if let Some(dns) = &s.dns {
        v.dns_value.set_text(dns.architecture.human_label());
        let mut detail = dns.summary.clone();
        if let Some(t) = &dns.resolv_conf_target {
            detail.push_str(&format!("\n/etc/resolv.conf → {t}"));
        }
        if let Some(p) = &dns.problem {
            detail.push_str(&format!("\n{p}"));
        }
        v.dns_detail.set_text(&detail);
        v.dns_fix_btn.set_visible(s.dns_fix.is_some());
    }
    // Config dropdown: in-place splice to avoid feedback loops.
    let names: Vec<String> = s.configs.iter().map(|c| c.name.clone()).collect();
    *v.cfg_names.borrow_mut() = names.clone();
    if let Some(model) = v.cfg_combo.model() {
        if let Some(list) = model.downcast_ref::<gtk4::StringList>() {
            let current = list.n_items();
            let wanted = names.len() as u32;
            let strs: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
            if current != wanted {
                list.splice(0, current, &strs);
            } else {
                // Update labels if order changed.
                let mut same = true;
                for (i, n) in names.iter().enumerate() {
                    if list.string(i as u32).as_deref() != Some(n.as_str()) {
                        same = false;
                        break;
                    }
                }
                if !same {
                    list.splice(0, current, &strs);
                }
            }
        }
    }
    if let Some(sel) = &s.selected {
        if let Some(pos) = names.iter().position(|n| n == sel) {
            if v.cfg_combo.selected() != pos as u32 {
                v.combo_guard.set(true);
                v.cfg_combo.set_selected(pos as u32);
                v.combo_guard.set(false);
            }
        }
    }
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn clear_box(b: &gtk4::Box) {
    while let Some(c) = b.first_child() {
        b.remove(&c);
    }
}

fn add_check(b: &gtk4::Box, label: &str, ok: bool) {
    let text = format!("{} {label}", if ok { "✓" } else { "✗" });
    let row = gtk4::Label::new(Some(&text));
    row.set_xalign(0.0);
    row.add_css_class(if ok { "td-check-ok" } else { "td-check-bad" });
    b.append(&row);
}

fn add_pending(b: &gtk4::Box, label: &str) {
    let row = gtk4::Label::new(Some(&format!("… {label}")));
    row.set_xalign(0.0);
    row.add_css_class("dim-label");
    b.append(&row);
}
