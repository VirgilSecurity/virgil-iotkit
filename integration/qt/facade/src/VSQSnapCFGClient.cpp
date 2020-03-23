//  Copyright (C) 2015-2020 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#include <virgil/iot/qt/VSQIoTKit.h>

#include <cstdio>
#include <cstring>

using namespace VirgilIoTKit;

VSQSnapCfgClient::VSQSnapCfgClient() {
    m_snapService = vs_snap_cfg_client();
}

void
VSQSnapCfgClient::onConfigureDevices() {
    qDebug() << "Configure ssid:<" << m_ssid << "> pass:<" << m_pass << "> account:<" << m_account << ">";

    if (m_ssid.length() >= VS_CFG_STR_MAX) {
        VS_LOG_ERROR("SSID string is longer than %d", VS_CFG_STR_MAX);
    }

    if (m_pass.length() >= VS_CFG_STR_MAX) {
        VS_LOG_ERROR("Password string is longer than %d", VS_CFG_STR_MAX);
    }

    if (m_account.length() >= VS_CFG_STR_MAX) {
        VS_LOG_ERROR("Account string is longer than %d", VS_CFG_STR_MAX);
    }

    vs_cfg_wifi_configuration_t config;
    ::strcpy(reinterpret_cast<char *>(config.ssid), m_ssid.toStdString().c_str());
    ::strcpy(reinterpret_cast<char *>(config.pass), m_pass.toStdString().c_str());
    ::strcpy(reinterpret_cast<char *>(config.account), m_account.toStdString().c_str());
    if (VS_CODE_OK != vs_snap_cfg_wifi_configure_device(vs_snap_netif_routing(),
                                 vs_snap_broadcast_mac(),
                                 &config)) {
        VS_LOG_ERROR("Cannot configure device");
    }

    // TODO: Fix it
    // need to receive response
    auto timer = new QTimer;
    connect(timer, &QTimer::timeout, [this](){
        emit this->fireConfigurationDone(true);
    });
    connect(timer, &QTimer::timeout, timer, &QTimer::deleteLater);
    timer->setSingleShot(true);
    timer->start(1000);
}

void
VSQSnapCfgClient::onSetConfigData(QString ssid, QString pass, QString account) {
    m_ssid = ssid;
    m_pass = pass;
    m_account = account;
}
