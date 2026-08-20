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
