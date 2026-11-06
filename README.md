# NetworkManager OpenVPN SSO Plugin

A NetworkManager VPN plugin that adds OAuth 2.0 / OIDC Single Sign-On (SSO) support for OpenVPN connections.

[![CI](https://github.com/quinnjr/network-manager-openvpn-sso/actions/workflows/ci.yml/badge.svg)](https://github.com/quinnjr/network-manager-openvpn-sso/actions/workflows/ci.yml)
[![Release](https://github.com/quinnjr/network-manager-openvpn-sso/actions/workflows/release.yml/badge.svg)](https://github.com/quinnjr/network-manager-openvpn-sso/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Browser-based SSO authentication** - Opens your default browser for OAuth/OIDC login
- **Automatic OAuth discovery** - Discovers authentication URLs from the OpenVPN server
- **Desktop notifications** - Shows connection status via system notifications
- **Full NetworkManager integration** - Works seamlessly with NetworkManager and network applets

## Installation

### Arch Linux

```bash
# From AUR or download from releases
sudo pacman -U networkmanager-openvpn-sso-*.pkg.tar.zst
```

### Debian / Ubuntu

```bash
sudo dpkg -i networkmanager-openvpn-sso_*_amd64.deb
sudo apt-get install -f  # Install any missing dependencies
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install networkmanager-openvpn-sso-*.x86_64.rpm
```

### Other Linux Distributions

```bash
# Download and extract the tarball
tar -xzf nm-openvpn-sso-service-linux-x86_64.tar.gz

# Run the install script
sudo ./install.sh
```

## Usage

### Importing an OpenVPN Configuration

1. Import your `.ovpn` file using NetworkManager:

```bash
nmcli connection import type openvpn file your-vpn-config.ovpn
```

2. Modify the connection to use the SSO plugin:

```bash
# Get the connection name
nmcli connection show | grep vpn

# Update to use SSO plugin
nmcli connection modify "your-vpn-name" vpn.service-type org.freedesktop.NetworkManager.openvpn-sso
```

3. Connect to the VPN:

```bash
nmcli connection up "your-vpn-name"
```

Your default browser will open for SSO authentication. After successful login, the VPN connection will be established automatically.

### Using with Network Manager GUI

#### GNOME

The VPN connection will appear in your system's network settings and can be activated from there. When connecting, your browser will open for authentication.

#### KDE Plasma

This project includes a native **plasma-nm UI plugin** that integrates directly with KDE Plasma's network applet. When installed, you can:

- Create, configure, and manage OpenVPN SSO connections from Plasma's network settings
- Import `.ovpn` files directly through the Plasma UI
- Connect and disconnect from the system tray network applet

The plugin is built automatically during installation if KDE dependencies are available.

**If the plugin is not installed**, you can still use:

1. **Command line**: `nmcli connection up "your-vpn-name"`
2. **nm-connection-editor**: GTK-based GUI that works on KDE
3. **vpn-sso-connect**: Helper script with KDialog integration (installed with this package)

## Requirements

- NetworkManager
- OpenVPN
- D-Bus
- A graphical session (for browser-based authentication)

## Building from Source

### Prerequisites

```bash
# Arch Linux
sudo pacman -S rust cargo dbus openssl pkgconf

# For KDE Plasma integration (optional)
sudo pacman -S extra-cmake-modules qt6-base networkmanager-qt kio ki18n kcoreaddons plasma-nm

# Debian/Ubuntu
sudo apt-get install rustc cargo libdbus-1-dev libssl-dev pkg-config

# Fedora
sudo dnf install rust cargo dbus-devel openssl-devel pkg-config
```

### Build

```bash
git clone https://github.com/quinnjr/network-manager-openvpn-sso.git
cd network-manager-openvpn-sso
cargo build --release
```

### Install

```bash
sudo ./install.sh
```

### Uninstall

```bash
sudo ./uninstall.sh
```

## Configuration

The plugin doesn't store session tokens. Each connection starts with a browser login, and the session then lasts as long as the server allows: OpenVPN renews it on renegotiation with the token the server issued (`auth-gen-token`). When the server rejects that token, the plugin ends the connection and NetworkManager reports it as failed; connect again to log in.

## Troubleshooting

### Browser doesn't open

Ensure you have a default browser set and that `xdg-open` or your browser is accessible. The plugin will try multiple methods to open the browser:

1. `xdg-open` run in the user's session via `systemd-run --user`
2. `xdg-open` run via `runuser -u <user>` if the above fails
3. A direct browser launch via `runuser -u <user>`, trying in order: `vivaldi-stable`, `vivaldi`, `firefox`, `chromium`, `google-chrome-stable`, `brave`

### Connection times out

Check the NetworkManager logs for details:

```bash
journalctl -u NetworkManager -f
```

### VPN connects but no network access

Verify that the VPN routes are correctly applied:

```bash
ip route | grep tun
```

### KDE Plasma shows "missing support" message

This means the plasma-nm UI plugin is not installed. Rebuild with KDE dependencies available:

```bash
# Arch Linux
sudo pacman -S extra-cmake-modules qt6-base networkmanager-qt kio ki18n kcoreaddons plasma-nm
sudo ./install.sh
```

The VPN still works without the plugin—use `nmcli` or `nm-connection-editor` to connect.

## How It Works

1. NetworkManager activates the VPN connection
2. The plugin starts OpenVPN with management interface enabled
3. OpenVPN connects to the server and receives an SSO authentication URL
4. The plugin opens your browser to the authentication URL
5. After successful authentication, the server provides credentials
6. The plugin completes the VPN connection and configures networking

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

- [GitHub Issues](https://github.com/quinnjr/network-manager-openvpn-sso/issues)

---

Made with ❤️ by [Joseph R. Quinn](https://github.com/quinnjr)
