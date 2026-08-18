// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

#include "openvpnssoauth.h"

#include <QLabel>
#include <QVBoxLayout>
#include <KLocalizedString>

OpenVpnSsoAuthWidget::OpenVpnSsoAuthWidget(const NetworkManager::VpnSetting::Ptr &setting,
                                            const QStringList &hints,
                                            QWidget *parent)
    : SettingWidget(setting, hints, parent)
{
    // hints intentionally unused; browser-based SSO requires no NetworkManager secrets
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
