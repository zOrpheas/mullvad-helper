#!/usr/bin/env bash
# Mullvad Helper installer for Arch Linux.
# Installs release binaries, .desktop entry, icon, and polkit policy.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Building release binaries..."
cargo build --release

echo "==> Installing binaries to /usr/bin (needs sudo)..."
sudo install -Dm755 target/release/mullvad-helper /usr/bin/mullvad-helper
sudo install -Dm755 target/release/mullvad-helper-cli /usr/bin/mullvad-helper-cli
sudo install -Dm755 target/release/mullvad-helper-privileged /usr/bin/mullvad-helper-privileged

echo "==> Installing desktop entry, icon, polkit policy..."
sudo install -Dm644 packaging/io.github.mullvadhelper.MullvadHelper.desktop /usr/share/applications/io.github.mullvadhelper.MullvadHelper.desktop
sudo install -Dm644 assets/icon.png /usr/share/icons/hicolor/512x512/apps/mullvad-helper.png
sudo install -Dm644 packaging/io.github.mullvadhelper.policy /usr/share/polkit-1/actions/io.github.mullvadhelper.policy
sudo gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true

echo "==> Verifying..."
mullvad-helper-cli --version

echo ""
echo "Done. Launch with: mullvad-helper"
echo "(or find 'Mullvad Helper' in your app launcher)"
echo "It asks for your password once per launch, then connects/disconnects freely."
