// App shell: window + two pages + channel + timer + tray.
use crate::state::{Job, UiMsg, backends};
use crate::worker::WorkerHandle;
use gtk4::prelude::*;
use ksni::blocking::TrayMethods;
use libadwaita::prelude::*;
use std::cell::Cell;
use std::rc::Rc;

pub struct App {
    pub window: libadwaita::ApplicationWindow,
    pub stack: gtk4::Stack,
    pub back_btn: gtk4::Button,
    pub stack_btn: gtk4::Button,
    pub main: crate::view_main::MainView,
    pub configs: crate::view_configs::ConfigsView,
    pub worker: WorkerHandle,
    pub toasts: libadwaita::ToastOverlay,
    /// None when no tray host (e.g. Waybar's `tray` module) is running.
    pub tray: Option<ksni::blocking::Handle<crate::tray::Tray>>,
    pub on_top: Cell<bool>,
}

pub fn build_ui(app: &libadwaita::Application) {
    // Launched again while running in the background: just show the window.
    if let Some(w) = app.windows().first() {
        w.present();
        return;
    }
    load_css();
    crate::hyprland::float_window();
    let be = backends();
    let window = libadwaita::ApplicationWindow::builder()
        .application(app)
        .title("Mullvad Helper")
        .default_width(400)
        .default_height(600)
        .build();
    let header = libadwaita::HeaderBar::new();
    header.set_title_widget(Some(&libadwaita::WindowTitle::new(
        "Mullvad Helper",
        "",
    )));
    let back_btn = gtk4::Button::from_icon_name("go-previous-symbolic");
    back_btn.set_tooltip_text(Some("Back"));
    back_btn.set_visible(false);
    header.pack_start(&back_btn);
    let stack_btn = gtk4::Button::from_icon_name("emblem-system-symbolic");
    stack_btn.set_tooltip_text(Some("Servers & settings"));
    let min_btn = gtk4::Button::from_icon_name("window-minimize-symbolic");
    min_btn.set_tooltip_text(Some("Minimize"));
    header.pack_end(&min_btn);
    header.pack_end(&stack_btn);
    let stack = gtk4::Stack::new();
    stack.set_transition_type(gtk4::StackTransitionType::SlideLeftRight);
    stack.set_vexpand(true);
    let main = crate::view_main::build();
    let configs = crate::view_configs::build();
    stack.add_named(&main.page, Some("main"));
    stack.add_named(&configs.page, Some("configs"));
    let col = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    col.append(&header);
    col.append(&stack);
    let toasts = libadwaita::ToastOverlay::new();
    toasts.set_child(Some(&col));
    window.set_content(Some(&toasts));
    {
        // Hyprland has no minimize: hide to the tray instead.
        let w = window.clone();
        min_btn.connect_clicked(move |_| {
            if crate::hyprland::active() {
                w.set_visible(false);
            } else {
                w.minimize();
            }
        });
    }
    let (tx, rx) = async_channel::bounded::<UiMsg>(32);
    let tray = crate::tray::Tray {
        tx: tx.clone(),
        window_visible: true,
        connected: false,
        status: crate::state::Health::Disconnected.label(),
    }
    .spawn()
    .map_err(|e| tracing::warn!("tray icon unavailable: {e}"))
    .ok();
    let worker = crate::worker::spawn(be, tx);
    let app = Rc::new(App {
        window,
        stack,
        back_btn,
        stack_btn,
        main,
        configs,
        worker,
        toasts,
        tray,
        on_top: Cell::new(crate::settings::Settings::load().on_top),
    });
    {
        let a = app.clone();
        app.stack_btn.connect_clicked(move |_| {
            a.stack.set_visible_child_name("configs");
            a.back_btn.set_visible(true);
            a.stack_btn.set_visible(false);
            a.worker.send(Job::RefreshFull);
        });
    }
    {
        let a = app.clone();
        app.back_btn.connect_clicked(move |_| {
            a.stack.set_visible_child_name("main");
            a.back_btn.set_visible(false);
            a.stack_btn.set_visible(true);
        });
    }
    {
        let a = app.clone();
        glib::spawn_future_local(async move {
            while let Ok(msg) = rx.recv().await {
                match msg {
                    UiMsg::Snap(s) => {
                        crate::view_main::render(&a.main, &s);
                        crate::view_configs::render(&a.configs, &s, &a.worker);
                        if let Some(t) = &a.tray {
                            t.update(|t| {
                                t.connected = s.active_iface.is_some();
                                t.status = s.health.label();
                            });
                        }
                    }
                    UiMsg::Toast(t) => {
                        a.toasts.add_toast(libadwaita::Toast::new(&t));
                    }
                    UiMsg::Show => a.window.present(),
                    UiMsg::Kill => a.worker.send(Job::Quit),
                    UiMsg::Quit => {
                        if let Some(app) = a.window.application() {
                            app.quit();
                        }
                    }
                }
            }
        });
    }
    crate::view_main::wire(&app);
    crate::view_configs::wire(&app);
    wire_window(&app);
    app.window.present();
    {
        let a = app.clone();
        glib::timeout_add_seconds_local(5, move || {
            if a.stack.visible_child_name().as_deref() == Some("main") {
                a.worker.send(Job::Refresh);
            }
            glib::ControlFlow::Continue
        });
    }
}

fn wire_window(app: &Rc<App>) {
    {
        let a = app.clone();
        app.window.connect_close_request(move |_| {
            ask_close(&a);
            glib::Propagation::Stop
        });
    }
    {
        // Every show maps a fresh Hyprland window, so re-apply "on top".
        let a = app.clone();
        app.window.connect_map(move |_| {
            let on = a.on_top.get();
            glib::timeout_add_local_once(std::time::Duration::from_millis(150), move || {
                crate::hyprland::set_on_top(on)
            });
        });
    }
    {
        let a = app.clone();
        app.window.connect_visible_notify(move |w| {
            if let Some(t) = &a.tray {
                let visible = w.is_visible();
                t.update(|t| t.window_visible = visible);
            }
        });
    }
    let row = &app.configs.on_top;
    row.set_active(app.on_top.get());
    if !crate::hyprland::active() {
        row.set_sensitive(false);
        row.set_subtitle("Only supported on Hyprland");
    }
    let a = app.clone();
    row.connect_active_notify(move |r| {
        let on = r.is_active();
        a.on_top.set(on);
        crate::settings::Settings { on_top: on }.save();
        crate::hyprland::set_on_top(on);
    });
}

fn ask_close(a: &Rc<App>) {
    let d = libadwaita::AlertDialog::new(
        Some("Close Mullvad Helper?"),
        Some("Silent keeps the VPN running in the background (find it in your tray).\nKill disconnects the VPN and quits."),
    );
    d.add_responses(&[("cancel", "Cancel"), ("kill", "Kill"), ("silent", "Silent")]);
    d.set_response_appearance("kill", libadwaita::ResponseAppearance::Destructive);
    d.set_response_appearance("silent", libadwaita::ResponseAppearance::Suggested);
    d.set_default_response(Some("silent"));
    d.set_close_response("cancel");
    let a2 = a.clone();
    d.connect_response(None, move |_, r| match r {
        "kill" => a2.worker.send(Job::Quit),
        "silent" => a2.window.set_visible(false),
        _ => {}
    });
    d.present(Some(&a.window));
}

fn load_css() {
    let provider = gtk4::CssProvider::new();
    provider.load_from_data(APP_CSS);
    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().expect("display"),
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

const APP_CSS: &str = "\
.td-hero { border-radius: 24px; padding: 28px 20px 22px 20px; transition: background 250ms ease; }\n\
.td-hero-off { background: alpha(@theme_fg_color, 0.05); }\n\
.td-hero-ok { background: alpha(@success_color, 0.16); }\n\
.td-hero-wait { background: alpha(@warning_color, 0.16); }\n\
.td-status-ok { color: @success_color; }\n\
.td-status-wait, .td-status-warn { color: @warning_color; }\n\
.td-status-off { color: alpha(@theme_fg_color, 0.45); }\n\
.td-big { font-size: 24px; font-weight: 800; }\n\
.td-primary { padding: 10px 48px; font-size: 16px; font-weight: 700; }\n\
.td-tech { font-family: monospace; font-size: 11px; }\n\
.td-check-ok { color: @success_color; }\n\
.td-check-bad { color: @error_color; }\n\
.td-banner-err { border-radius: 14px; border: 1px solid alpha(@error_color, 0.4); background: alpha(@error_color, 0.12); padding: 12px 14px; }\n\
.td-banner-info { border-radius: 14px; border: 1px solid alpha(@accent_color, 0.35); background: alpha(@accent_color, 0.10); padding: 12px 14px; }\n\
";
