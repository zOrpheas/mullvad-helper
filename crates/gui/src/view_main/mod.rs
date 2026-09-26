// Main (status) page: struct here; build, render and wire in submodules.
mod build;
mod cards;
mod render;
mod wire;

pub use build::build;
pub use render::render;
pub use wire::wire;

use std::cell::Cell;
use std::rc::Rc;

pub struct MainView {
    pub page: gtk4::ScrolledWindow,
    pub col: gtk4::Box,
    pub hero: gtk4::Box,
    pub dot: gtk4::Image,
    pub title: gtk4::Label,
    pub subtitle: gtk4::Label,
    pub busy_row: gtk4::Box,
    pub spinner: gtk4::Spinner,
    pub busy_label: gtk4::Label,
    pub primary_btn: gtk4::Button,
    pub banner: gtk4::Box,
    pub banner_label: gtk4::Label,
    pub tech_expander: gtk4::Expander,
    pub tech_label: gtk4::Label,
    pub banner_dismiss: gtk4::Button,
    pub checks_box: gtk4::Box,
    pub ip_value: gtk4::Label,
    pub hs_value: gtk4::Label,
    pub traffic_value: gtk4::Label,
    pub dns_value: gtk4::Label,
    pub dns_detail: gtk4::Label,
    pub dns_fix_btn: gtk4::Button,
    pub cfg_combo: gtk4::DropDown,
    pub cfg_names: Rc<std::cell::RefCell<Vec<String>>>,
    pub combo_guard: Rc<Cell<bool>>,
    pub import_btn: gtk4::Button,
    pub ip_btn: gtk4::Button,
    pub doctor_btn: gtk4::Button,
}
