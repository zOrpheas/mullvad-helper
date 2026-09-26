//! mullvad-helper-privileged: minimal root helper invoked via pkexec/polkit.
//!
//! Modes:
//!   * one-shot: `mullvad-helper-privileged <verb> [args]` (prompts each time)
//!   * daemon:   `mullvad-helper-privileged daemon <socket>` (one prompt, serves
//!               many requests over the socket until the app exits)
//!
//! Every verb re-validates its inputs here in the helper — never in the GUI:
//!   tunnel names    [A-Za-z0-9_-]{1,15}
//!   systemd units   wg-quick@<tunnel>.service only
//!   packages        small allow-list (see ops::allowed_package)
mod daemon;
mod ops;
mod ops_core;
mod ops_read;

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: mullvad-helper-privileged <verb> [args]");
        eprintln!("       mullvad-helper-privileged daemon <socket>");
        exit(2);
    }
    if args[1] == "daemon" {
        if args.len() != 3 {
            eprintln!("usage: mullvad-helper-privileged daemon <socket>");
            exit(2);
        }
        daemon::run_daemon(&args[2]);
        return;
    }
    match ops::run(&args[1], &args[2..]) {
        Ok(out) => {
            if !out.is_empty() {
                println!("{out}");
            }
        }
        Err(e) => {
            eprintln!("mullvad-helper-privileged: {e}");
            exit(1);
        }
    }
}
