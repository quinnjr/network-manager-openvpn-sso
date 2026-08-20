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
