// Privileged operations. Every function returns Result so the same code
// backs both the one-shot CLI mode and the long-running daemon mode.
//
// SECURITY: callers must never be handed key material. `wg_status` therefore
// returns a pre-parsed, sanitised summary instead of raw `wg show dump`
// output (whose first field is the interface private key).
use crate::ops_core::{install_config, repair_perms, remove_config, systemctl, wg_quick};
use crate::ops_read::{install_packages, list_configs, wg_status};
use std::path::PathBuf;

pub fn valid_tunnel(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Only `wg-quick@<tunnel>.service` units may ever be touched.
pub fn valid_unit(unit: &str) -> bool {
    match unit
        .strip_prefix("wg-quick@")
        .and_then(|s| s.strip_suffix(".service"))
    {
        Some(inner) => valid_tunnel(inner),
        None => false,
    }
}

/// Only these pacman packages may ever be installed through the helper.
pub fn allowed_package(name: &str) -> bool {
    matches!(
        name,
        "wireguard-tools" | "systemd-resolvconf" | "nftables" | "iproute2" | "polkit"
    )
}

pub fn wg_dir() -> PathBuf {
    PathBuf::from("/etc/wireguard")
}

/// Dispatch a verb. `args` excludes the verb itself.
pub fn run(verb: &str, args: &[String]) -> Result<String, String> {
    match verb {
        "install-config" => {
            let (staging, name) = two(args, "install-config <staging> <name>")?;
            install_config(staging, name)
        }
        "repair-perms" => repair_perms(),
        "wg-quick-up" => wg_quick(true, one(args, "wg-quick-up <name>")?),
        "wg-quick-down" => wg_quick(false, one(args, "wg-quick-down <name>")?),
        "systemctl-enable" => systemctl(true, one(args, "systemctl-enable <unit>")?),
        "systemctl-disable" => systemctl(false, one(args, "systemctl-disable <unit>")?),
        "remove-config" => remove_config(one(args, "remove-config <name>")?),
        "list-configs" => {
            expect_none(args)?;
            list_configs()
        }
        "wg-status" => wg_status(one(args, "wg-status <name>")?),
        "install-packages" => install_packages(args),
        other => Err(format!("unknown verb '{other}'")),
    }
}

fn usage(s: &str) -> String {
    format!("usage: {s}")
}

fn expect_none(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err("unexpected argument".into())
    }
}

fn one<'a>(args: &'a [String], usage_str: &str) -> Result<&'a str, String> {
    if args.len() != 1 {
        return Err(usage(usage_str));
    }
    Ok(args[0].as_str())
}

fn two<'a>(args: &'a [String], usage_str: &str) -> Result<(&'a str, &'a str), String> {
    if args.len() != 2 {
        return Err(usage(usage_str));
    }
    Ok((args[0].as_str(), args[1].as_str()))
}
