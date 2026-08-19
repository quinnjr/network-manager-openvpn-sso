#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Joseph R. Quinn
#
# Uninstall script for nm-openvpn-sso NetworkManager plugin

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

PREFIX="${PREFIX:-/usr}"
LIBDIR="${LIBDIR:-$PREFIX/lib}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"

info "Removing files..."
rm -f "$LIBDIR/nm-openvpn-sso-service"
rm -f "$LIBDIR/NetworkManager/VPN/nm-openvpn-sso-service.name"
rm -f "$PREFIX/share/dbus-1/system.d/org.freedesktop.NetworkManager.openvpn-sso.conf"
rm -f "$PREFIX/bin/vpn-sso-connect"
rm -f "$PREFIX/share/applications/vpn-sso-connect.desktop"
rm -f "$LIBDIR/qt6/plugins/plasma/network/vpn/plasmanetworkmanagement_openvpnssoui.so"

info "Reloading daemons..."
systemctl daemon-reload
dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>/dev/null || true

info "Restarting NetworkManager..."
systemctl restart NetworkManager

info "Uninstall complete!"
