// Wire main-view buttons.
use crate::app::App;
use crate::state::Job;
use gtk4::prelude::*;
use std::rc::Rc;

pub fn wire(app: &Rc<App>) {
    {
        let a = app.clone();
        app.main.primary_btn.connect_clicked(move |_| {
            a.worker.send(Job::ToggleSelected);
        });
    }
    {
        let a = app.clone();
        app.main.banner_dismiss.connect_clicked(move |_| {
            a.worker.send(Job::DismissNotice);
        });
    }
    {
        let a = app.clone();
        app.main.cfg_combo.connect_selected_notify(move |combo| {
            if a.main.combo_guard.get() {
                return;
            }
            let pos = combo.selected() as usize;
            let names = a.main.cfg_names.borrow();
            if let Some(name) = names.get(pos) {
                a.worker.send(Job::Select(name.clone()));
            }
        });
    }
    {
        let a = app.clone();
        let window = app.window.clone();
        app.main.import_btn.connect_clicked(move |_| {
            let dialog = gtk4::FileChooserDialog::new(
                Some("Import WireGuard .conf"),
                Some(&window),
                gtk4::FileChooserAction::Open,
                &[
                    ("Cancel", gtk4::ResponseType::Cancel),
                    ("Import", gtk4::ResponseType::Accept),
                ],
            );
            let filter = gtk4::FileFilter::new();
            filter.set_name(Some("WireGuard configs (*.conf)"));
            filter.add_pattern("*.conf");
            dialog.add_filter(&filter);
            let w = a.worker.clone();
            dialog.connect_response(move |d, r| {
                if r == gtk4::ResponseType::Accept {
                    if let Some(f) = d.file() {
                        if let Some(path) = f.path() {
                            w.send(Job::Import(path));
                        }
                    }
                }
                d.destroy();
            });
            dialog.show();
        });
    }
    {
        let a = app.clone();
        app.main.ip_btn.connect_clicked(move |_| {
            a.worker.send(Job::CheckIp);
        });
    }
    {
        let a = app.clone();
        app.main.doctor_btn.connect_clicked(move |_| {
            a.worker.send(Job::Doctor);
            a.stack.set_visible_child_name("configs");
            a.back_btn.set_visible(true);
            a.stack_btn.set_visible(false);
        });
    }
    {
        let a = app.clone();
        app.main.dns_fix_btn.connect_clicked(move |_| {
            a.worker.send(Job::ApplyDnsFix);
        });
    }
}
