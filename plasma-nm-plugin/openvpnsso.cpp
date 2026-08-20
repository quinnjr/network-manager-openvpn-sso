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
#include <QRegularExpression>
#include <QStringList>

extern "C" {
#include <NetworkManager.h>
}

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

// Import deliberately stores only the source config-file path under the "config" data key.
// Field extraction (remote/port/proto) is deferred to the Rust service (src/config.rs) at
// connect time, and the widget's gateway/port/protocol fields are optional user overrides
// layered on top of that file — parsing them out here would be redundant.
VpnUiPlugin::ImportResult OpenVpnSsoUiPlugin::importConnectionSettings(const QString &fileName)
{
    if (!QFile::exists(fileName)) {
        return ImportResult::fail(i18n("File not found: %1", fileName));
    }

    const QFileInfo fileInfo(fileName);
    const QString connectionName = fileInfo.completeBaseName();
    const QString absolutePath = fileInfo.absoluteFilePath();

    // Create an NMConnection using libnm C API
    NMConnection *connection = nm_simple_connection_new();

    // Set connection settings
    NMSettingConnection *sConn = NM_SETTING_CONNECTION(nm_setting_connection_new());
    nm_connection_add_setting(connection, NM_SETTING(sConn));

    g_object_set(sConn,
                 NM_SETTING_CONNECTION_ID, connectionName.toUtf8().constData(),
                 NM_SETTING_CONNECTION_TYPE, NM_SETTING_VPN_SETTING_NAME,
                 NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
                 nullptr);

    // Set VPN settings
    NMSettingVpn *sVpn = NM_SETTING_VPN(nm_setting_vpn_new());
    nm_connection_add_setting(connection, NM_SETTING(sVpn));

    g_object_set(sVpn,
                 NM_SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.openvpn-sso",
                 nullptr);
    nm_setting_vpn_add_data_item(sVpn, "config", absolutePath.toUtf8().constData());

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

    if (!QFile::exists(configPath)) {
        return ExportResult::fail(i18n("Source configuration file not found: %1", configPath));
    }

    QFile sourceFile(configPath);
    if (!sourceFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return ExportResult::fail(i18n("Failed to read configuration file: %1", configPath));
    }
    const QString sourceContents = QString::fromUtf8(sourceFile.readAll());
    sourceFile.close();

    // Gateway/port/protocol overrides stashed by OpenVpnSsoSettingWidget::setting().
    const QString remoteOverride = data.value(QStringLiteral("remote"));
    const QString portOverride = data.value(QStringLiteral("port"));
    const QString protoOverride = data.value(QStringLiteral("proto"));

    QString outputContents = sourceContents;

    if (!remoteOverride.isEmpty() || !portOverride.isEmpty() || !protoOverride.isEmpty()) {
        QStringList lines = sourceContents.split(QLatin1Char('\n'));

        int remoteLineIdx = -1;
        int portLineIdx = -1;
        int protoLineIdx = -1;

        static const QRegularExpression keywordRe(QStringLiteral("^\\s*(\\S+)"));
        static const QRegularExpression whitespaceRe(QStringLiteral("\\s+"));

        for (int i = 0; i < lines.size(); ++i) {
            const QString trimmed = lines.at(i).trimmed();
            if (trimmed.isEmpty() || trimmed.startsWith(QLatin1Char('#')) || trimmed.startsWith(QLatin1Char(';'))) {
                continue;
            }
            const QRegularExpressionMatch match = keywordRe.match(trimmed);
            if (!match.hasMatch()) {
                continue;
            }
            const QString keyword = match.captured(1);
            if (keyword == QLatin1String("remote") && remoteLineIdx < 0) {
                remoteLineIdx = i;
            } else if (keyword == QLatin1String("port") && portLineIdx < 0) {
                portLineIdx = i;
            } else if (keyword == QLatin1String("proto") && protoLineIdx < 0) {
                protoLineIdx = i;
            }
        }

        // "remote" accepts an optional embedded port and protocol: "remote <host> [port] [proto]".
        QString remoteHost;
        QString remotePort;
        QString remoteProto;
        if (remoteLineIdx >= 0) {
            const QStringList tokens = lines.at(remoteLineIdx).trimmed().split(whitespaceRe, Qt::SkipEmptyParts);
            if (tokens.size() > 1) {
                remoteHost = tokens.at(1);
            }
            if (tokens.size() > 2) {
                remotePort = tokens.at(2);
            }
            if (tokens.size() > 3) {
                remoteProto = tokens.at(3);
            }
        }

        if (!remoteOverride.isEmpty()) {
            remoteHost = remoteOverride;
        }
        // Only fold the port/proto override into the remote line if the source already used
        // that embedded form there; otherwise it belongs on a standalone directive below.
        if (!portOverride.isEmpty() && remoteLineIdx >= 0 && !remotePort.isEmpty()) {
            remotePort = portOverride;
        }
        if (!protoOverride.isEmpty() && remoteLineIdx >= 0 && !remoteProto.isEmpty()) {
            remoteProto = protoOverride;
        }

        if (remoteLineIdx >= 0) {
            QString newRemoteLine = QStringLiteral("remote %1").arg(remoteHost);
            if (!remotePort.isEmpty()) {
                newRemoteLine += QLatin1Char(' ') + remotePort;
            }
            if (!remoteProto.isEmpty()) {
                newRemoteLine += QLatin1Char(' ') + remoteProto;
            }
            lines[remoteLineIdx] = newRemoteLine;
        } else if (!remoteOverride.isEmpty()) {
            lines.append(QStringLiteral("remote %1").arg(remoteOverride));
        }

        if (!portOverride.isEmpty() && remotePort != portOverride) {
            if (portLineIdx >= 0) {
                lines[portLineIdx] = QStringLiteral("port %1").arg(portOverride);
            } else {
                lines.append(QStringLiteral("port %1").arg(portOverride));
            }
        }

        if (!protoOverride.isEmpty() && remoteProto != protoOverride) {
            if (protoLineIdx >= 0) {
                lines[protoLineIdx] = QStringLiteral("proto %1").arg(protoOverride);
            } else {
                lines.append(QStringLiteral("proto %1").arg(protoOverride));
            }
        }

        outputContents = lines.join(QLatin1Char('\n'));
    }

    if (QFile::exists(fileName)) {
        QFile::remove(fileName);
    }

    QFile destFile(fileName);
    if (!destFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return ExportResult::fail(i18n("Failed to write configuration to: %1", fileName));
    }
    destFile.write(outputContents.toUtf8());
    destFile.close();

    return ExportResult::pass();
}

#include "openvpnsso.moc"
