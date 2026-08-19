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
