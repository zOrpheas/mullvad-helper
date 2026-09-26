// Wire configs-page buttons.
use crate::app::App;
use crate::state::Job;
use gtk4::prelude::*;
use std::rc::Rc;

pub fn wire(app: &Rc<App>) {
    {
        let a = app.clone();
        app.configs.install_btn.connect_clicked(move |_| {
            a.worker.send(Job::InstallMissing);
        });
    }
    {
        let a = app.clone();
        app.configs.repair_btn.connect_clicked(move |_| {
            a.worker.send(Job::RepairPerms);
        });
    }
}
