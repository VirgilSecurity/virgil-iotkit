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
#include <virgil/iot/qt/netif/VSQNetifBLEEnumerator.h>

void VSQNetifBLEEnumerator::onDeviceDiscovered(const QBluetoothDeviceInfo & deviceInfo) {
    if (deviceInfo.coreConfigurations() & QBluetoothDeviceInfo::LowEnergyCoreConfiguration
      && !deviceInfo.name().isEmpty()) {
        m_devices[deviceInfo.name()] = deviceInfo;
        qDebug() << "[VIRGIL] Device Discovered : " << deviceInfo.name()
                 << " : "
                 << deviceInfo.deviceUuid();
        emit fireDevicesListUpdated();
    }
}

void VSQNetifBLEEnumerator::onDiscoveryFinished() {
    if (!QObject::sender()) return;
    QObject::sender()->deleteLater();
    emit fireDiscoveryFinished();
}

QStringList VSQNetifBLEEnumerator::devicesList() const {
    return m_devices.keys();
}

void VSQNetifBLEEnumerator::select(QString devName) const {
    if (m_devices.keys().contains(devName)) {
        emit fireDeviceSelected(m_devices[devName]);
    }
}

void VSQNetifBLEEnumerator::startDiscovery() {
    m_devices.clear();
    // Create a discovery agent and connect to its signals
    QBluetoothDeviceDiscoveryAgent * discoveryAgent = new QBluetoothDeviceDiscoveryAgent(this);
    discoveryAgent->setInquiryType(QBluetoothDeviceDiscoveryAgent::LimitedInquiry);
    connect(discoveryAgent, &QBluetoothDeviceDiscoveryAgent::deviceDiscovered,
            this, &VSQNetifBLEEnumerator::onDeviceDiscovered);

    connect(discoveryAgent, &QBluetoothDeviceDiscoveryAgent::finished,
            this, &VSQNetifBLEEnumerator::onDiscoveryFinished);

    connect(discoveryAgent, &QBluetoothDeviceDiscoveryAgent::canceled,
            this, &VSQNetifBLEEnumerator::onDiscoveryFinished);

    connect(discoveryAgent, SIGNAL(error(QBluetoothDeviceDiscoveryAgent::Error)),
            this, SLOT(onDiscoveryFinished()));

    discoveryAgent->start(QBluetoothDeviceDiscoveryAgent::LowEnergyMethod);
}

