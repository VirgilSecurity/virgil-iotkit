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

#include <virgil/iot/qt/protocols/snap/VSQNetifBase.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapServiceBase.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapINFOClient.h>
#include <virgil/iot/qt/VSQIoTKit.h>

using namespace VirgilIoTKit;

bool
VSQIoTKitFacade::init(const VSQFeatures &features, const VSQImplementations &impl, const VSQAppConfig &appConfig) {

    m_features = features;
    m_impl = impl;
    m_appConfig = appConfig;

    vs_logger_init(appConfig.logLevel());

    try {
        // SNAP entities
        if (features.hasSnap()) {
            initSnap();
        }

        return true;

    } catch (QString &descr) {
        VS_LOG_CRITICAL("Error during Virgil IoT KIT initialization : %s", descr.toStdString().c_str());
        return false;
    }
}

void
VSQIoTKitFacade::initSnap() {

    Q_CHECK_PTR(m_impl.netif());

    if (vs_snap_init(m_impl.netif(),
                     m_appConfig.manufactureId(),
                     m_appConfig.deviceType(),
                     m_appConfig.deviceSerial(),
                     m_appConfig.deviceRoles()) != VirgilIoTKit::VS_CODE_OK) {
        throw QString("Unable to initialize SNAP");
    }

    if (m_features.hasFeature(VSQFeatures::SNAP_INFO_CLIENT)) {
        registerService(VSQSnapInfoClient::instance());

        if (m_impl.netif().connectionState() == QAbstractSocket::BoundState) {
            VSQSnapInfoClient::instance().startFullPolling();
        }

        QObject::connect(
                &m_impl.netif(), &VSQNetifBase::fireStateChanged, this, &VSQIoTKitFacade::restartInfoClientPolling);

    }

    if (m_features.hasFeature(VSQFeatures::SNAP_SNIFFER)) {
        m_snapSniffer = decltype(m_snapSniffer)::create(m_appConfig.snifferConfig(), &m_impl.netif());
    }
}

void
VSQIoTKitFacade::registerService(VSQSnapServiceBase &service) {
    if (vs_snap_register_service(service.serviceInterface()) != VirgilIoTKit::VS_CODE_OK) {
        throw QString("Unable to register SNAP's %1 service").arg(service.serviceName());
    }
}

void
VSQIoTKitFacade::restartInfoClientPolling(QAbstractSocket::SocketState connectionState) {
    if (connectionState == QAbstractSocket::BoundState) {
        VSQSnapInfoClient::instance().startFullPolling();
    }
}
