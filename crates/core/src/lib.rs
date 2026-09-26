//! Mullvad Helper core: shared models, WireGuard config parser, redaction, logging.
//!
//! This crate contains NO privileged operations and NO shell-outs.
//! It is safe to unit-test without root or WireGuard installed.

pub mod logging;
pub mod metadata_cache;
pub mod models;
pub mod parser;
pub mod redact;

pub use models::*;
pub use parser::{ParsedConfig, WireGuardParseError, parse_wireguard_config};
pub use redact::redact_secrets;
