# Maintainer: Joseph R. Quinn <quinn.josephr@protonmail.com>
pkgname=networkmanager-openvpn-sso
pkgver=0.3.1
pkgrel=1
pkgdesc="NetworkManager VPN plugin for OpenVPN with SSO/OAuth authentication"
arch=('x86_64')
url="https://github.com/quinnjr/network-manager-openvpn-sso"
license=('MIT')
depends=('networkmanager' 'openvpn' 'libsecret' 'dbus')
makedepends=('cargo' 'rust' 'extra-cmake-modules' 'qt6-base' 'networkmanager-qt' 'kio' 'ki18n' 'kcoreaddons')
optdepends=('plasma-nm: KDE Plasma network manager integration')
provides=('networkmanager-openvpn-sso')
conflicts=('networkmanager-openvpn-sso-git')
# !lto: makepkg's -flto CFLAGS produce GCC bitcode objects for ring's C code
# that rust's lld cannot link (undefined ring_core_* symbols)
options=('!lto')
source=()
sha256sums=()

build() {
    cd "$startdir"
    cargo build --release --locked

    # Build plasma-nm plugin if plasma-nm and KDE dependencies are available
    if pkg-config --exists "KF6NetworkManagerQt" && [[ -f /usr/lib/libplasmanm_editor.so ]]; then
        cmake -B plasma-nm-plugin/build -S plasma-nm-plugin
        cmake --build plasma-nm-plugin/build
    fi
}

package() {
    cd "$startdir"

    # Install binary (same location pattern as nm-openvpn-service)
    install -Dm755 "target/release/nm-openvpn-sso-service" \
        "$pkgdir/usr/lib/nm-openvpn-sso-service"

    # Install NetworkManager VPN plugin name file
    install -Dm644 "data/nm-openvpn-sso-service.name" \
        "$pkgdir/usr/lib/NetworkManager/VPN/nm-openvpn-sso-service.name"

    # Install D-Bus policy (allows root to own the bus name)
    install -Dm644 "data/org.freedesktop.NetworkManager.openvpn-sso.conf" \
        "$pkgdir/usr/share/dbus-1/system.d/nm-openvpn-sso-service.conf"

    # Install helper script for KDE/CLI users
    install -Dm755 "data/vpn-sso-connect.sh" \
        "$pkgdir/usr/bin/vpn-sso-connect"

    # Install desktop entry
    install -Dm644 "data/vpn-sso-connect.desktop" \
        "$pkgdir/usr/share/applications/vpn-sso-connect.desktop"

    # Install plasma-nm plugin if built
    if [[ -f "plasma-nm-plugin/build/plasmanetworkmanagement_openvpnssoui.so" ]]; then
        install -Dm755 "plasma-nm-plugin/build/plasmanetworkmanagement_openvpnssoui.so" \
            "$pkgdir/usr/lib/qt6/plugins/plasma/network/vpn/plasmanetworkmanagement_openvpnssoui.so"
    fi

    # Install license
    install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
