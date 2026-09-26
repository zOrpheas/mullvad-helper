# Mullvad Helper

A small, beginner-friendly Linux desktop app for connecting to Mullvad VPN
with WireGuard. Import the `.conf` file from your Mullvad account, press
**Connect**, done. No terminal, no networking knowledge needed.

Built with Rust + GTK4/libadwaita. The app never runs as root: it asks for
your password **once per launch** and uses a tiny, locked-down helper for the
few steps that need admin rights.

> Unofficial community project, not affiliated with or endorsed by Mullvad VPN AB.

## Features

- One-click connect/disconnect, clear "Protected / Not protected" status
- Honest status: only says *Protected* after a fresh handshake, working
  internet **and** a verified VPN public IP
- Import Mullvad WireGuard `.conf` files (stored root-only in `/etc/wireguard`)
- Start a tunnel on boot, delete servers, built-in troubleshooter
- DNS setup detection with a one-click fix
- Small floating window; optional *Keep window on top* (Settings, Hyprland)
- Closing asks: **Silent** keeps the VPN running in the background with a
  tray icon (Waybar `tray` module), **Kill** disconnects and quits
- CLI for scripting: `mullvad-helper-cli`

## Install (Arch Linux)

```sh
sudo pacman -S --needed rustup base-devel pkgconf gtk4 libadwaita polkit \
    wireguard-tools systemd-resolvconf
rustup default stable
git clone https://github.com/<you>/mullvad-helper.git
cd mullvad-helper
./install.sh
```

`install.sh` builds the release binaries and installs:

| File | Where |
|---|---|
| `mullvad-helper` (app) | `/usr/bin/` |
| `mullvad-helper-cli` | `/usr/bin/` |
| `mullvad-helper-privileged` (root helper) | `/usr/bin/` |
| Launcher entry | `/usr/share/applications/` |
| Icon | `/usr/share/icons/hicolor/512x512/apps/` |
| Polkit policy | `/usr/share/polkit-1/actions/` |

`systemd-resolvconf` is the right DNS shim if you use `systemd-resolved`;
use `openresolv` otherwise.

## Usage

1. Open **Mullvad Helper** from your app launcher and enter your password once.
2. Press **+** next to *Server* and pick your Mullvad `.conf` file.
3. Press **Connect**.

Settings (the gear icon) are saved in `~/.config/mullvad-helper/settings.json`.

Never run the app with `sudo`.

### CLI

```sh
mullvad-helper-cli doctor                            # check your system
mullvad-helper-cli import ~/Downloads/de-fra-wg-001.conf
mullvad-helper-cli connect de-fra-wg-001
mullvad-helper-cli status
mullvad-helper-cli disconnect de-fra-wg-001
```

## Troubleshooting

- **Logs:** `~/.local/state/mullvad-helper/mullvad-helper.log` (keys are
  written as `[REDACTED]`). Errors in the app also have a *Technical details*
  section.
- **Stuck on "Connecting…":** the server hasn't answered in 3 minutes, or the
  IP check hasn't run yet. Press **Check my IP**.
- **App seems frozen:** a password dialog is probably waiting behind the window.
- **Anything else:** press **Troubleshoot** for a full system check.

## How it works

```
crates/
  core/               config parser, models, key redaction, logging (no shell-outs)
  backend/            WireGuard, DNS, systemd, privileges, dependency + network checks
  privileged-helper/  minimal root helper started via pkexec
  cli/                mullvad-helper-cli
  gui/                GTK4/libadwaita app
    src/view_main/      status page
    src/view_configs/   servers & troubleshooting page
    src/worker/         background job queue (connect, import, refresh…)
packaging/            .desktop entry, polkit policy
assets/               app icon
```

- **One password per launch.** The app starts
  `pkexec mullvad-helper-privileged daemon <socket>` once. Later actions go
  over a user-only Unix socket in `$XDG_RUNTIME_DIR`. The helper exits as soon
  as the app closes, so root never outlives the app.
- **The UI never blocks.** A single worker thread owns all state and runs
  jobs from a FIFO queue; the GTK side only renders immutable snapshots.
  Background refreshes are coalesced, and buttons disable while a job runs.

### Privileged operations

The helper re-validates every argument itself: tunnel names must match
`[A-Za-z0-9_-]{1,15}`, only `wg-quick@*.service` units are allowed, and only
`wireguard-tools`, `systemd-resolvconf`, `nftables`, `iproute2` and `polkit`
can be installed.

| Action | Helper verb | What it does |
|---|---|---|
| Import | `install-config` | copy to `/etc/wireguard/<name>.conf` (`0600 root:root`, dir `0700`) |
| Repair | `repair-perms` | reset `/etc/wireguard` permissions |
| Connect / Disconnect | `wg-quick-up` / `wg-quick-down` | `wg-quick up/down <name>` |
| Start on boot | `systemctl-enable` / `systemctl-disable` | toggle `wg-quick@<name>.service` |
| Delete | `remove-config` | delete the `.conf` (refused while connected) |
| Install deps | `install-packages` | `pacman -S --needed` from the allow-list |

### Security

- Private and preshared keys never reach the UI, logs, or the IP-check service.
- `PostUp`/`PreUp`/`PostDown`/`PreDown` hooks run as root via wg-quick, so the
  app points them out and refuses to install risky ones silently.
- Kill-switch rules are detected and shown, never added silently.

## Development

```sh
cargo build --release
cargo test --workspace     # no VPN or root needed
./target/release/mullvad-helper
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
