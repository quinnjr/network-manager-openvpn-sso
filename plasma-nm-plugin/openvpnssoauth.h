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
