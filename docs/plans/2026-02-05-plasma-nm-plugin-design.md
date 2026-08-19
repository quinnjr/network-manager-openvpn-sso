# Plasma-NM VPN UI Plugin for OpenVPN SSO - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a KDE Plasma NetworkManager UI plugin so users can create, configure, and manage OpenVPN SSO connections directly from the Plasma network applet.

**Architecture:** A Qt6/KF6 C++ shared library implementing the `VpnUiPlugin` interface from plasma-nm. The plugin provides a configuration widget (config file path, server overrides) and an auth widget (informational SSO message). It links against `libplasmanm_editor.so` for base classes and `KF6::NetworkManagerQt` for NM data types. Since plasma-nm doesn't ship development headers, we vendor the required headers in our project.

**Tech Stack:** C++17, Qt6 (Core/Widgets/DBus), KDE Frameworks 6 (CoreAddons, I18n, KIOWidgets, NetworkManagerQt), CMake with ECM (extra-cmake-modules), KPluginFactory.

---

## File Structure

```
plasma-nm-plugin/
├── CMakeLists.txt                              # Build system
├── include/                                    # Vendored plasma-nm headers
│   └── vpnuiplugin.h                          # Already exists
├── openvpnsso.h                               # Main plugin class header
├── openvpnsso.cpp                             # Plugin factory + widget/askUser/import/export
├── openvpnssowidget.h                         # Configuration widget header
├── openvpnssowidget.cpp                       # Configuration widget implementation
├── openvpnssoauth.h                           # Auth widget header
├── openvpnssoauth.cpp                         # Auth widget implementation
├── openvpnsso.ui                              # Qt Designer UI form
└── plasmanetworkmanagement_openvpnssoui.json  # KDE plugin metadata
```

---

### Task 1: Create Plugin Metadata JSON

**Files:**
- Create: `plasma-nm-plugin/plasmanetworkmanagement_openvpnssoui.json`

**Step 1: Create the metadata file**

```json
{
    "KPlugin": {
        "Authors": [
            {
                "Email": "quinn.josephr@protonmail.com",
                "Name": "Joseph R. Quinn"
            }
        ],
        "Category": "VPNService",
        "Description": "Compatible with OpenVPN servers using SSO/OAuth authentication",
        "EnabledByDefault": false,
        "Icon": "",
        "License": "MIT",
        "Name": "OpenVPN SSO",
        "Version": "0.1.0",
        "Website": "https://github.com/quinnjr/network-manager-openvpn-sso"
    },
    "X-NetworkManager-Services": "org.freedesktop.NetworkManager.openvpn-sso"
}
```

**Step 2: Commit**

```bash
git add plasma-nm-plugin/plasmanetworkmanagement_openvpnssoui.json
git commit -m "feat(plasma): add KDE plugin metadata for openvpn-sso"
```

---

### Task 2: Create CMakeLists.txt Build System

**Files:**
- Create: `plasma-nm-plugin/CMakeLists.txt`

**Step 1: Create the CMake build file**

This CMakeLists is standalone (not nested under a parent). Users build it separately:
`cd plasma-nm-plugin && mkdir build && cd build && cmake .. && make`

```cmake
cmake_minimum_required(VERSION 3.22)
project(plasmanetworkmanagement_openvpnssoui VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package(ECM REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
include(KDEInstallDirs)
include(KDECMakeSettings)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets DBus)
find_package(KF6 REQUIRED COMPONENTS CoreAddons I18n KIOWidgets NetworkManagerQt)

add_library(plasmanetworkmanagement_openvpnssoui MODULE
    openvpnsso.cpp
    openvpnsso.h
    openvpnssowidget.cpp
    openvpnssowidget.h
    openvpnssoauth.cpp
    openvpnssoauth.h
)

# The .ui file will be processed by AUTOUIC automatically

target_include_directories(plasmanetworkmanagement_openvpnssoui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link against plasma-nm editor library (installed by plasma-nm package)
find_library(PLASMANM_EDITOR_LIB plasmanm_editor REQUIRED)

target_link_libraries(plasmanetworkmanagement_openvpnssoui
    ${PLASMANM_EDITOR_LIB}
    Qt6::Core
    Qt6::Widgets
    Qt6::DBus
    KF6::CoreAddons
    KF6::I18n
    KF6::KIOWidgets
    KF6::NetworkManagerQt
)

# Suppress warnings about missing export header (we define the macro ourselves)
target_compile_definitions(plasmanetworkmanagement_openvpnssoui PRIVATE
    PLASMANM_EDITOR_EXPORT=
)

install(TARGETS plasmanetworkmanagement_openvpnssoui
    DESTINATION ${KDE_INSTALL_PLUGINDIR}/plasma/network/vpn
)
```

**Step 2: Commit**

```bash
git add plasma-nm-plugin/CMakeLists.txt
git commit -m "feat(plasma): add CMake build system for plasma-nm plugin"
```

---

### Task 3: Create Qt Designer UI Form

**Files:**
- Create: `plasma-nm-plugin/openvpnsso.ui`

**Step 1: Create the UI file**

The UI provides:
- Config file path selector (KUrlRequester for .ovpn file browsing)
- Optional gateway/server override
- Optional port override
- Optional protocol selector (UDP/TCP/Auto)
- Informational label about SSO

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ui version="4.0">
 <class>OpenVpnSsoWidget</class>
 <widget class="QWidget" name="OpenVpnSsoWidget">
  <property name="geometry">
   <rect>
    <x>0</x>
    <y>0</y>
    <width>400</width>
    <height>300</height>
   </rect>
  </property>
  <layout class="QFormLayout" name="formLayout">
   <item row="0" column="0" colspan="2">
    <widget class="QLabel" name="ssoInfoLabel">
     <property name="text">
      <string>This VPN uses browser-based SSO authentication. No username or password is needed here.</string>
     </property>
     <property name="wordWrap">
      <bool>true</bool>
     </property>
    </widget>
   </item>
   <item row="1" column="0">
    <widget class="QLabel" name="configLabel">
     <property name="text">
      <string>Configuration file:</string>
     </property>
    </widget>
   </item>
   <item row="1" column="1">
    <widget class="KUrlRequester" name="configPath">
     <property name="placeholderText">
      <string>/path/to/config.ovpn</string>
     </property>
    </widget>
   </item>
   <item row="2" column="0">
    <widget class="QLabel" name="gatewayLabel">
     <property name="text">
      <string>Gateway (optional):</string>
     </property>
    </widget>
   </item>
   <item row="2" column="1">
    <widget class="QLineEdit" name="gateway">
     <property name="placeholderText">
      <string>Use server from config file</string>
     </property>
    </widget>
   </item>
   <item row="3" column="0">
    <widget class="QLabel" name="portLabel">
     <property name="text">
      <string>Port (optional):</string>
     </property>
    </widget>
   </item>
   <item row="3" column="1">
    <widget class="QSpinBox" name="port">
     <property name="specialValueText">
      <string>Automatic</string>
     </property>
     <property name="minimum">
      <number>0</number>
     </property>
     <property name="maximum">
      <number>65535</number>
     </property>
     <property name="value">
      <number>0</number>
     </property>
    </widget>
   </item>
   <item row="4" column="0">
    <widget class="QLabel" name="protoLabel">
     <property name="text">
      <string>Protocol:</string>
     </property>
    </widget>
   </item>
   <item row="4" column="1">
    <widget class="QComboBox" name="protocol">
    </widget>
   </item>
  </layout>
 </widget>
 <customwidgets>
  <customwidget>
   <class>KUrlRequester</class>
   <extends>QWidget</extends>
   <header>KUrlRequester</header>
  </customwidget>
 </customwidgets>
 <resources/>
 <connections/>
</ui>
```

**Step 2: Commit**

```bash
git add plasma-nm-plugin/openvpnsso.ui
git commit -m "feat(plasma): add Qt Designer UI form for VPN configuration"
```

---

### Task 4: Create Configuration Widget

**Files:**
- Create: `plasma-nm-plugin/openvpnssowidget.h`
- Create: `plasma-nm-plugin/openvpnssowidget.cpp`

**Step 1: Create the header**

```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

#ifndef PLASMANM_OPENVPNSSO_WIDGET_H
#define PLASMANM_OPENVPNSSO_WIDGET_H

#include "settingwidget.h"
#include <NetworkManagerQt/VpnSetting>

namespace Ui {
class OpenVpnSsoWidget;
}

class OpenVpnSsoSettingWidget : public SettingWidget
{
    Q_OBJECT
public:
    explicit OpenVpnSsoSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent = nullptr);
    ~OpenVpnSsoSettingWidget() override;

    void loadConfig(const NetworkManager::Setting::Ptr &setting) override;
    QVariantMap setting() const override;
    bool isValid() const override;

private:
    Ui::OpenVpnSsoWidget *m_ui;
    NetworkManager::VpnSetting::Ptr m_setting;
};

#endif // PLASMANM_OPENVPNSSO_WIDGET_H
```

**Step 2: Create the implementation**

```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

#include "openvpnssowidget.h"
#include "ui_openvpnsso.h"

#include <QFile>
#include <KLocalizedString>

OpenVpnSsoSettingWidget::OpenVpnSsoSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
    : SettingWidget(setting, parent)
    , m_ui(new Ui::OpenVpnSsoWidget)
    , m_setting(setting)
{
    m_ui->setupUi(this);

    // Set up the config file filter
    m_ui->configPath->setNameFilter(i18n("OpenVPN config (*.ovpn *.conf);;All files (*)"));

    // Populate protocol combo box
    m_ui->protocol->addItem(i18n("Automatic"), QString());
    m_ui->protocol->addItem(QStringLiteral("UDP"), QStringLiteral("udp"));
    m_ui->protocol->addItem(QStringLiteral("TCP"), QStringLiteral("tcp"));

    // Connect validity signals
    connect(m_ui->configPath, &KUrlRequester::textChanged, this, &OpenVpnSsoSettingWidget::slotWidgetChanged);

    if (setting && !setting->isNull()) {
        loadConfig(setting);
    }

    watchChangedSetting();
}

OpenVpnSsoSettingWidget::~OpenVpnSsoSettingWidget()
{
    delete m_ui;
}

void OpenVpnSsoSettingWidget::loadConfig(const NetworkManager::Setting::Ptr &setting)
{
    auto vpnSetting = setting.staticCast<NetworkManager::VpnSetting>();
    const NMStringMap data = vpnSetting->data();

    // Config file path
    const QString configPath = data.value(QStringLiteral("config"));
    if (!configPath.isEmpty()) {
        m_ui->configPath->setUrl(QUrl::fromLocalFile(configPath));
    }

    // Gateway / remote override
    const QString remote = data.value(QStringLiteral("remote"));
    if (!remote.isEmpty()) {
        m_ui->gateway->setText(remote);
    }

    // Port override
    const QString port = data.value(QStringLiteral("port"));
    if (!port.isEmpty()) {
        m_ui->port->setValue(port.toInt());
    }

    // Protocol
    const QString proto = data.value(QStringLiteral("proto"));
    const int protoIndex = m_ui->protocol->findData(proto);
    if (protoIndex >= 0) {
        m_ui->protocol->setCurrentIndex(protoIndex);
    }
}

QVariantMap OpenVpnSsoSettingWidget::setting() const
{
    NMStringMap data;

    // Config file path (required)
    const QUrl configUrl = m_ui->configPath->url();
    if (configUrl.isValid()) {
        data.insert(QStringLiteral("config"), configUrl.toLocalFile());
    }

    // Gateway override (optional)
    const QString gateway = m_ui->gateway->text().trimmed();
    if (!gateway.isEmpty()) {
        data.insert(QStringLiteral("remote"), gateway);
    }

    // Port override (optional - 0 means automatic)
    const int port = m_ui->port->value();
    if (port > 0) {
        data.insert(QStringLiteral("port"), QString::number(port));
    }

    // Protocol (optional)
    const QString proto = m_ui->protocol->currentData().toString();
    if (!proto.isEmpty()) {
        data.insert(QStringLiteral("proto"), proto);
    }

    NetworkManager::VpnSetting setting;
    setting.setServiceType(QStringLiteral("org.freedesktop.NetworkManager.openvpn-sso"));
    setting.setData(data);

    return setting.toMap();
}

bool OpenVpnSsoSettingWidget::isValid() const
{
    const QUrl configUrl = m_ui->configPath->url();
    return configUrl.isValid() && QFile::exists(configUrl.toLocalFile());
}
```

**Step 3: Commit**

```bash
git add plasma-nm-plugin/openvpnssowidget.h plasma-nm-plugin/openvpnssowidget.cpp
git commit -m "feat(plasma): add VPN configuration widget"
```

---

### Task 5: Create Auth Widget

**Files:**
- Create: `plasma-nm-plugin/openvpnssoauth.h`
- Create: `plasma-nm-plugin/openvpnssoauth.cpp`

**Step 1: Create the header**

```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

#ifndef PLASMANM_OPENVPNSSO_AUTH_H
#define PLASMANM_OPENVPNSSO_AUTH_H

#include "settingwidget.h"
#include <NetworkManagerQt/VpnSetting>

class OpenVpnSsoAuthWidget : public SettingWidget
{
    Q_OBJECT
public:
    explicit OpenVpnSsoAuthWidget(const NetworkManager::VpnSetting::Ptr &setting,
                                  const QStringList &hints,
                                  QWidget *parent = nullptr);
    ~OpenVpnSsoAuthWidget() override;

    QVariantMap setting() const override;
};

#endif // PLASMANM_OPENVPNSSO_AUTH_H
```

**Step 2: Create the implementation**

The auth widget is intentionally minimal - SSO auth happens in the browser, not in a password dialog. We just show an informational message and return empty secrets so NetworkManager proceeds to call our VPN service, which handles the browser-based flow.

```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

#include "openvpnssoauth.h"

#include <QLabel>
#include <QVBoxLayout>
#include <KLocalizedString>

OpenVpnSsoAuthWidget::OpenVpnSsoAuthWidget(const NetworkManager::VpnSetting::Ptr &setting,
                                            const QStringList &hints,
                                            QWidget *parent)
    : SettingWidget(setting, hints, parent)
{
    auto *layout = new QVBoxLayout(this);

    auto *label = new QLabel(this);
    label->setWordWrap(true);
    label->setText(i18n("This VPN uses Single Sign-On (SSO) authentication.\n\n"
                        "Your web browser will open automatically to complete authentication "
                        "when the connection starts."));
    layout->addWidget(label);

    layout->addStretch();

    setLayout(layout);
}

OpenVpnSsoAuthWidget::~OpenVpnSsoAuthWidget() = default;

QVariantMap OpenVpnSsoAuthWidget::setting() const
{
    // No secrets needed from the user - SSO is handled by the browser
    return {};
}
```

**Step 3: Commit**

```bash
git add plasma-nm-plugin/openvpnssoauth.h plasma-nm-plugin/openvpnssoauth.cpp
git commit -m "feat(plasma): add SSO auth widget (informational, browser-based)"
```

---

### Task 6: Create Main Plugin Class

**Files:**
- Create: `plasma-nm-plugin/openvpnsso.h`
- Create: `plasma-nm-plugin/openvpnsso.cpp`

**Step 1: Create the header**

```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

#ifndef PLASMANM_OPENVPNSSO_H
#define PLASMANM_OPENVPNSSO_H

#include "vpnuiplugin.h"
#include <QVariant>

class Q_DECL_EXPORT OpenVpnSsoUiPlugin : public VpnUiPlugin
{
    Q_OBJECT
public:
    explicit OpenVpnSsoUiPlugin(QObject *parent = nullptr, const QVariantList & = QVariantList());
    ~OpenVpnSsoUiPlugin() override;

    SettingWidget *widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent) override;
    SettingWidget *askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent) override;

    QString suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const override;
    QStringList supportedFileExtensions() const override;
    ImportResult importConnectionSettings(const QString &fileName) override;
    ExportResult exportConnectionSettings(const NetworkManager::ConnectionSettings::Ptr &connection, const QString &fileName) override;
};

#endif // PLASMANM_OPENVPNSSO_H
```

**Step 2: Create the implementation**

```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

#include "openvpnsso.h"
#include "openvpnssowidget.h"
#include "openvpnssoauth.h"

#include <KPluginFactory>
#include <KLocalizedString>
#include <NetworkManagerQt/ConnectionSettings>
#include <NetworkManagerQt/VpnSetting>

#include <QFile>
#include <QFileInfo>
#include <QTextStream>

K_PLUGIN_CLASS_WITH_JSON(OpenVpnSsoUiPlugin, "plasmanetworkmanagement_openvpnssoui.json")

OpenVpnSsoUiPlugin::OpenVpnSsoUiPlugin(QObject *parent, const QVariantList &)
    : VpnUiPlugin(parent)
{
}

OpenVpnSsoUiPlugin::~OpenVpnSsoUiPlugin() = default;

SettingWidget *OpenVpnSsoUiPlugin::widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
{
    return new OpenVpnSsoSettingWidget(setting, parent);
}

SettingWidget *OpenVpnSsoUiPlugin::askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent)
{
    return new OpenVpnSsoAuthWidget(setting, hints, parent);
}

QString OpenVpnSsoUiPlugin::suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const
{
    return connection->id() + QStringLiteral(".ovpn");
}

QStringList OpenVpnSsoUiPlugin::supportedFileExtensions() const
{
    return {QStringLiteral("*.ovpn"), QStringLiteral("*.conf")};
}

VpnUiPlugin::ImportResult OpenVpnSsoUiPlugin::importConnectionSettings(const QString &fileName)
{
    QFile file(fileName);
    if (!file.exists()) {
        return ImportResult::fail(i18n("File not found: %1", fileName));
    }

    const QFileInfo fileInfo(fileName);
    const QString connectionName = fileInfo.completeBaseName();

    auto *connection = new NMConnection;

    // Set connection properties
    auto connSettings = connection->settings();
    connSettings->setId(connectionName);
    connSettings->setConnectionType(NetworkManager::ConnectionSettings::Vpn);
    connSettings->setAutoconnect(false);

    // Set VPN properties
    auto vpnSetting = connSettings->setting(NetworkManager::Setting::Vpn).staticCast<NetworkManager::VpnSetting>();
    vpnSetting->setServiceType(QStringLiteral("org.freedesktop.NetworkManager.openvpn-sso"));

    NMStringMap data;
    data.insert(QStringLiteral("config"), QFileInfo(fileName).absoluteFilePath());
    vpnSetting->setData(data);

    return ImportResult::pass(connection);
}

VpnUiPlugin::ExportResult OpenVpnSsoUiPlugin::exportConnectionSettings(
    const NetworkManager::ConnectionSettings::Ptr &connection, const QString &fileName)
{
    auto vpnSetting = connection->setting(NetworkManager::Setting::Vpn).staticCast<NetworkManager::VpnSetting>();
    const NMStringMap data = vpnSetting->data();

    const QString configPath = data.value(QStringLiteral("config"));
    if (configPath.isEmpty()) {
        return ExportResult::fail(i18n("No configuration file path stored in this connection."));
    }

    // Copy the original .ovpn file to the export location
    if (QFile::exists(fileName)) {
        QFile::remove(fileName);
    }
    if (!QFile::copy(configPath, fileName)) {
        return ExportResult::fail(i18n("Failed to copy configuration to: %1", fileName));
    }

    return ExportResult::pass();
}

#include "openvpnsso.moc"
```

**Step 3: Commit**

```bash
git add plasma-nm-plugin/openvpnsso.h plasma-nm-plugin/openvpnsso.cpp
git commit -m "feat(plasma): add main VPN UI plugin with import/export support"
```

---

### Task 7: Add Vendored Headers

The system doesn't ship plasma-nm development headers, so we vendor the minimum required headers. The `vpnuiplugin.h` already exists. We need `settingwidget.h` — but we DON'T vendor its .cpp since we link against `libplasmanm_editor.so` at runtime.

**Files:**
- Create: `plasma-nm-plugin/include/settingwidget.h`

**Step 1: Create the vendored settingwidget.h**

Copy from upstream KDE plasma-nm, but replace the `#include "plasmanm_editor_export.h"` with our compile definition (we define `PLASMANM_EDITOR_EXPORT=` in CMake).

```cpp
// SPDX-FileCopyrightText: 2013 Jan Grulich <jgrulich@redhat.com>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
//
// Vendored from KDE plasma-nm for build compatibility.
// This header is provided by libplasmanm_editor.so at runtime.

#ifndef SETTING_WIDGET_H
#define SETTING_WIDGET_H

#ifndef PLASMANM_EDITOR_EXPORT
#define PLASMANM_EDITOR_EXPORT
#endif

#include <NetworkManagerQt/Setting>
#include <QWidget>

class PLASMANM_EDITOR_EXPORT SettingWidget : public QWidget
{
    Q_OBJECT
public:
    class EnumPasswordStorageType
    {
    public:
        enum PasswordStorageType {
            Store = 0,
            AlwaysAsk,
            NotRequired
        };
    };

    explicit SettingWidget(const NetworkManager::Setting::Ptr &setting = NetworkManager::Setting::Ptr(),
                          QWidget *parent = nullptr, Qt::WindowFlags f = {});
    explicit SettingWidget(const NetworkManager::Setting::Ptr &setting, const QStringList &hints,
                          QWidget *parent = nullptr, Qt::WindowFlags f = {});

    ~SettingWidget() override;

    virtual void loadConfig(const NetworkManager::Setting::Ptr &setting);
    virtual void loadSecrets(const NetworkManager::Setting::Ptr &setting);

    virtual QVariantMap setting() const = 0;

    void watchChangedSetting();

    QString type() const;

    virtual bool isValid() const
    {
        return true;
    }

protected Q_SLOTS:
    void slotWidgetChanged();

Q_SIGNALS:
    void validChanged(bool isValid);
    void settingChanged();

protected:
    QStringList m_hints;

private:
    QString m_type;
};

#endif // SETTING_WIDGET_H
```

**Step 2: Update vpnuiplugin.h**

The existing vendored `vpnuiplugin.h` includes headers that we don't have (`plasmanm_editor_export.h`, `nm-connection.h`). We need to update it to work with our vendored setup. Replace includes that reference plasma-nm internal files with our available equivalents.

Key changes:
- Replace `#include "plasmanm_editor_export.h"` with inline `#ifndef` guard
- Replace `#include "settingwidget.h"` - keep as-is (our vendored copy)
- Replace `#include "nm-connection.h"` with forward declaration + the system libnm header

Updated vpnuiplugin.h:

```cpp
// SPDX-FileCopyrightText: 2008 Will Stephenson <wstephenson@kde.org>
// SPDX-FileCopyrightText: 2013 Lukáš Tinkl <ltinkl@redhat.com>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
//
// Vendored from KDE plasma-nm for build compatibility.

#ifndef PLASMA_NM_VPN_UI_PLUGIN_H
#define PLASMA_NM_VPN_UI_PLUGIN_H

#ifndef PLASMANM_EDITOR_EXPORT
#define PLASMANM_EDITOR_EXPORT
#endif

#include <QMessageBox>
#include <QObject>
#include <QVariant>

#include <NetworkManagerQt/ConnectionSettings>
#include <NetworkManagerQt/GenericTypes>
#include <NetworkManagerQt/VpnSetting>

#include <KPluginFactory>

#include "settingwidget.h"

// Forward declaration - NMConnection is provided by libplasmanm_editor.so
class NMConnection;

class PLASMANM_EDITOR_EXPORT VpnUiPlugin : public QObject
{
    Q_OBJECT
public:
    enum ErrorType {
        NoError,
        NotImplemented,
        Error
    };

    explicit VpnUiPlugin(QObject *parent = nullptr, const QVariantList & = QVariantList());
    ~VpnUiPlugin() override;

    virtual SettingWidget *widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent) = 0;
    virtual SettingWidget *askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent) = 0;

    virtual QString suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const = 0;
    virtual QStringList supportedFileExtensions() const;

    struct ImportResult {
    private:
        NMConnection *m_connection;
        ErrorType m_error = NoError;
        QString m_errorMessage;

    public:
        operator bool() const;

        QString errorMessage() const;

        NMConnection *connection() const;

        static ImportResult fail(const QString &errorMessage);

        static ImportResult pass(NMConnection *connection);

        static ImportResult notImplemented();
    };

    virtual ImportResult importConnectionSettings(const QString &fileName);

    struct ExportResult {
    private:
        ErrorType m_error = NoError;
        QString m_errorMessage;

    public:
        operator bool() const;

        QString errorMessage() const;

        static ExportResult pass();

        static ExportResult fail(const QString &errorMessage);

        static ExportResult notImplemented();
    };

    virtual ExportResult exportConnectionSettings(const NetworkManager::ConnectionSettings::Ptr &connection, const QString &fileName);

    virtual QMessageBox::StandardButtons suggestedAuthDialogButtons() const;

    static KPluginFactory::Result<VpnUiPlugin> loadPluginForType(QObject *parent, const QString &serviceType);
};

#endif // PLASMA_NM_VPN_UI_PLUGIN_H
```

**Step 3: Commit**

```bash
git add plasma-nm-plugin/include/settingwidget.h plasma-nm-plugin/include/vpnuiplugin.h
git commit -m "feat(plasma): add vendored headers for build compatibility"
```

---

### Task 8: Build and Test

**Step 1: Install build dependencies**

```bash
sudo pacman -S --needed extra-cmake-modules qt6-base networkmanager-qt kio ki18n kcoreaddons plasma-nm
```

**Step 2: Build the plugin**

```bash
cd plasma-nm-plugin
mkdir -p build && cd build
cmake ..
make
```

**Step 3: Fix any compilation errors**

Address any issues that arise from the build.

**Step 4: Test install**

```bash
sudo install -Dm755 build/plasmanetworkmanagement_openvpnssoui.so /usr/lib/qt6/plugins/plasma/network/vpn/plasmanetworkmanagement_openvpnssoui.so
```

**Step 5: Verify the plugin loads**

Restart plasma-nm or KDE and check:
- Creating a new VPN connection should show "OpenVPN SSO" as an option
- The configuration widget should display correctly
- Importing a .ovpn file should work

**Step 6: Commit any build fixes**

```bash
git add -A plasma-nm-plugin/
git commit -m "fix(plasma): address build issues"
```

---

### Task 9: Update PKGBUILD and Install Scripts

**Files:**
- Modify: `PKGBUILD` - add plasma-nm plugin build and install steps
- Modify: `install.sh` - add plasma-nm plugin install
- Modify: `uninstall.sh` - add plasma-nm plugin uninstall

**Step 1: Update PKGBUILD**

Add to `makedepends`: `'extra-cmake-modules' 'qt6-base' 'networkmanager-qt' 'kio' 'ki18n' 'kcoreaddons'`
Add to `optdepends`: `'plasma-nm: KDE Plasma network manager integration'`

Add to `build()`:
```bash
# Build plasma-nm plugin if dependencies are available
if pkg-config --exists "KF6NetworkManagerQt"; then
    cmake -B plasma-nm-plugin/build -S plasma-nm-plugin
    cmake --build plasma-nm-plugin/build
fi
```

Add to `package()`:
```bash
# Install plasma-nm plugin if built
if [[ -f "plasma-nm-plugin/build/plasmanetworkmanagement_openvpnssoui.so" ]]; then
    install -Dm755 "plasma-nm-plugin/build/plasmanetworkmanagement_openvpnssoui.so" \
        "$pkgdir/usr/lib/qt6/plugins/plasma/network/vpn/plasmanetworkmanagement_openvpnssoui.so"
fi
```

**Step 2: Update install.sh**

Add a section that builds and installs the plasma plugin if KDE dependencies are available.

**Step 3: Update uninstall.sh**

Add removal of `/usr/lib/qt6/plugins/plasma/network/vpn/plasmanetworkmanagement_openvpnssoui.so`.

**Step 4: Commit**

```bash
git add PKGBUILD install.sh uninstall.sh
git commit -m "feat: add plasma-nm plugin to PKGBUILD and install scripts"
```

---

### Task 10: Update README

**Files:**
- Modify: `README.md`

**Step 1: Update the README**

Update the KDE section to note that the plasma-nm plugin is now included and works natively. Remove or update the workaround notes about "Plasma is missing support".

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README with plasma-nm plugin support"
```
