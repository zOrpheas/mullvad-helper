//! Backend: wg/dns/systemd/privilege/deps/netcheck/doctor/configs/errors.
//! UI and CLI talk to this layer; no shell commands leak into UI code.

pub mod command;
pub mod configs;
pub mod daemon_client;
pub mod deps;
pub mod dns;
pub mod doctor;
pub mod errors;
pub mod netcheck;
pub mod privilege;
pub mod systemd;
pub mod wireguard;
