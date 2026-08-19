#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Joseph R. Quinn
#
# Install script for nm-openvpn-sso NetworkManager plugin

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

# Detect installation prefix
PREFIX="${PREFIX:-/usr}"
LIBDIR="${LIBDIR:-$PREFIX/lib}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"

# Paths
NM_VPN_DIR="$LIBDIR/NetworkManager/VPN"
NM_PLUGIN_DIR="$LIBDIR"
DBUS_SYSTEM_CONF="$PREFIX/share/dbus-1/system.d"
DESKTOP_DIR="$PREFIX/share/applications"
BIN_DIR="$PREFIX/bin"

# Build the project
info "Building nm-openvpn-sso..."
if command -v cargo &> /dev/null; then
    cargo build --release
else
    error "Cargo not found. Please install Rust: https://rustup.rs/"
fi

BINARY="target/release/nm-openvpn-sso-service"
if [[ ! -f "$BINARY" ]]; then
    error "Build failed - binary not found"
fi

# Create directories
info "Creating directories..."
mkdir -p "$NM_VPN_DIR"
mkdir -p "$NM_PLUGIN_DIR"
mkdir -p "$DBUS_SYSTEM_CONF"
mkdir -p "$DESKTOP_DIR"
mkdir -p "$BIN_DIR"

# Install binary
info "Installing binary to $NM_PLUGIN_DIR..."
install -m 755 "$BINARY" "$NM_PLUGIN_DIR/nm-openvpn-sso-service"

# Install NetworkManager plugin file
info "Installing NetworkManager plugin configuration..."
install -m 644 data/nm-openvpn-sso-service.name "$NM_VPN_DIR/"

# Install D-Bus policy
info "Installing D-Bus policy..."
install -m 644 data/org.freedesktop.NetworkManager.openvpn-sso.conf "$DBUS_SYSTEM_CONF/"

# Install helper script
info "Installing VPN helper script..."
install -m 755 data/vpn-sso-connect.sh "$BIN_DIR/vpn-sso-connect"

# Install desktop file
info "Installing desktop entry..."
install -m 644 data/vpn-sso-connect.desktop "$DESKTOP_DIR/"

# Build and install plasma-nm plugin if KDE dependencies are available
PLASMA_INSTALLED=false
if command -v cmake &> /dev/null && pkg-config --exists "KF6NetworkManagerQt" 2>/dev/null && [[ -f "$LIBDIR/libplasmanm_editor.so" ]]; then
    info "Building plasma-nm plugin for KDE Plasma..."
    cmake -B plasma-nm-plugin/build -S plasma-nm-plugin 2>/dev/null
    if cmake --build plasma-nm-plugin/build 2>/dev/null; then
        PLASMA_PLUGIN_DIR="$LIBDIR/qt6/plugins/plasma/network/vpn"
        mkdir -p "$PLASMA_PLUGIN_DIR"
        install -m 755 plasma-nm-plugin/build/plasmanetworkmanagement_openvpnssoui.so "$PLASMA_PLUGIN_DIR/"
        info "Plasma-nm plugin installed."
        PLASMA_INSTALLED=true
    else
        warn "Failed to build plasma-nm plugin (KDE integration will not be available)."
    fi
else
    warn "KDE dependencies not found - skipping plasma-nm plugin build."
    warn "KDE Plasma users: install extra-cmake-modules, qt6-base, networkmanager-qt, kio, ki18n, kcoreaddons, plasma-nm and re-run."
fi

# Reload daemons
info "Reloading system daemons..."
dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>/dev/null || true

# Update desktop database
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

# Restart NetworkManager to pick up the new plugin
info "Restarting NetworkManager..."
systemctl restart NetworkManager

info "Installation complete!"
echo ""
echo "The OpenVPN SSO plugin is now available in NetworkManager."
echo ""
echo "To add a VPN connection:"
echo "  nmcli connection import type openvpn file your-config.ovpn"
echo "  nmcli connection modify \"connection-name\" vpn.service-type org.freedesktop.NetworkManager.openvpn-sso"
echo ""
echo "To connect:"
echo "  nmcli connection up \"connection-name\""
echo ""
echo "Or use the 'VPN SSO Connect' app from your application menu."
if [[ "$PLASMA_INSTALLED" != "true" ]]; then
    echo ""
    echo "Note: KDE Plasma users may see 'missing support' in the network applet."
    echo "Install KDE dependencies and re-run to enable native Plasma integration."
fi
