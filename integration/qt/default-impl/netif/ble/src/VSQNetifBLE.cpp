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
#include <virgil/iot/qt/netif/VSQNetifBLE.h>

const QString VSQNetifBLE::_serviceUuid("0000abf0-0000-1000-8000-00805f9b34fb");
const QString VSQNetifBLE::_serviceUuidTx("0000abf1-0000-1000-8000-00805f9b34fb");
const QString VSQNetifBLE::_serviceUuidRx("0000abf2-0000-1000-8000-00805f9b34fb");
const size_t VSQNetifBLE::_sendSizeLimit(20);

VSQNetifBLE::VSQNetifBLE() : m_canCommunicate(false),
    m_leController(QSharedPointer <QLowEnergyController> (nullptr)),
    m_leService(QSharedPointer <QLowEnergyService> (nullptr)) {
}

bool
VSQNetifBLE::init() {
    // TODO: Fix it
    m_mac = VSQMac("01:02:03:04:05:06");
    return true;
}

bool
VSQNetifBLE::deinit() {
    deactivate();
    return true;
}

bool
VSQNetifBLE::tx(const QByteArray &data) {
    if (!isActive()) return false;

    qDebug() << "Send data lenght : " << data.size();
    qDebug() << data.toHex();

    m_dataForSend = data;
    m_sendPos = 0;

    sendPartOfData();

    return true;
}

QString
VSQNetifBLE::macAddr() const {

    return m_mac;
}

void VSQNetifBLE::onDeviceConnected() {
    m_leController->discoverServices();
    m_availableServices.clear();
}

void VSQNetifBLE::onServiceDiscovered(QBluetoothUuid uuid) {
    m_availableServices << uuid;
    qDebug() << "Service discovered : " << uuid;
}

bool VSQNetifBLE::prepareNotificationReceiver() {
    if (!isActive()) return false;

    QLowEnergyCharacteristic notificationCharacteristic;
    foreach (const QLowEnergyCharacteristic &ch, m_leService->characteristics()) {
        if (QBluetoothUuid(_serviceUuidRx) == ch.uuid()) {
            notificationCharacteristic = ch;
            break;
        }
    }

    if (notificationCharacteristic.isValid()) {
        QLowEnergyDescriptor notification = notificationCharacteristic.descriptor(QBluetoothUuid::ClientCharacteristicConfiguration);
        if (!notification.isValid()) {
            qWarning() << "ERROR: Invalid notification";
            return false;
        }

        connect(m_leService.data(), SIGNAL(characteristicChanged(const QLowEnergyCharacteristic &, const QByteArray &)),
                this, SLOT(onNotification(const QLowEnergyCharacteristic &, const QByteArray &)));

        connect(m_leService.data(), SIGNAL(characteristicWritten(const QLowEnergyCharacteristic &, const QByteArray &)),
                this, SLOT(onCharacteristicWritten()));

        // enable notification
        m_leService->writeDescriptor(notification, QByteArray::fromHex("0100"));
        return true;
    }

    qWarning() << "ERROR: Can't set notification handler";
    return false;
}

void VSQNetifBLE::onServiceDetailsDiscovered(QLowEnergyService::ServiceState serviceState) {
    if (QLowEnergyService::ServiceDiscovered != serviceState) return;

    const QList<QLowEnergyCharacteristic> chars = m_leService->characteristics();
    bool canRead(false);
    bool canWrite(false);

    foreach (const QLowEnergyCharacteristic &ch, chars) {
        qDebug() << ">>> " << ch.uuid();
        if (QBluetoothUuid(_serviceUuidRx) == ch.uuid()) {
            canRead = true;
        } else if (QBluetoothUuid(_serviceUuidTx) == ch.uuid()) {
            canWrite = true;
        }

        if (canRead && canWrite) break;
    }

    if (!canRead || !canWrite || !prepareNotificationReceiver()) {
        onDeviceDisconnected();
        qWarning() << "Cannot start communication";
    }

    qDebug() << "VSQNetifBLE::onConnected";
    m_canCommunicate = true;

    tx(QByteArray::fromStdString("Hello World !!!"));
}

void VSQNetifBLE::onServicesDiscoveryFinished() {
    m_leService = QSharedPointer <QLowEnergyService> (m_leController->createServiceObject(QBluetoothUuid(_serviceUuid)));
    if (m_leService.isNull()) {
        qWarning() << "Cannot create service for uuid = " << _serviceUuid;
        onDeviceDisconnected();
        return;
    }
    connect(m_leService.data(), SIGNAL(stateChanged(QLowEnergyService::ServiceState)),
            this, SLOT(onServiceDetailsDiscovered(QLowEnergyService::ServiceState)));
    m_leService->discoverDetails();
}

void VSQNetifBLE::onServicesDiscoveryError(QLowEnergyController::Error error) {
    Q_UNUSED(error)
    onDeviceDisconnected();
}

void VSQNetifBLE::onDeviceDisconnected() {
    m_canCommunicate = false;
}

bool VSQNetifBLE::onOpenDevice(const QBluetoothDeviceInfo device) {
    deactivate();
    VSQNetifBase::resetPacketForced();  // Force packet reset

    m_leController = QSharedPointer <QLowEnergyController> (new QLowEnergyController(device));
    connect(m_leController.data(), SIGNAL(connected()),
            this, SLOT(onDeviceConnected()));
    connect(m_leController.data(), SIGNAL(error(QLowEnergyController::Error)),
            this, SLOT(onServicesDiscoveryError(QLowEnergyController::Error)));
    connect(m_leController.data(), SIGNAL(disconnected()),
            this, SLOT(onDeviceDisconnected()));
    connect(m_leController.data(), SIGNAL(serviceDiscovered(QBluetoothUuid)),
            this, SLOT(onServiceDiscovered(QBluetoothUuid)));
    connect(m_leController.data(), SIGNAL(discoveryFinished()),
            this, SLOT(onServicesDiscoveryFinished()));

    m_leController->connectToDevice();

    return true;
}

void VSQNetifBLE::deactivate() {
    if (!m_leController.isNull()) {
        m_leController->disconnectFromDevice();
    }
    m_canCommunicate = false;
}

void VSQNetifBLE::onNotification(const QLowEnergyCharacteristic & characteristic, const QByteArray & data) {
    Q_UNUSED(characteristic)
    if (isActive()) {
        qDebug() << "Notification : " << data.size();
        processData(data.data());
    }
}

bool VSQNetifBLE::sendPartOfData() {
    if (!isActive()) {
        m_sendPos = 0;
        m_dataForSend.clear();
        return false;
    }
    QLowEnergyCharacteristic writeCharacteristic;
    foreach (const QLowEnergyCharacteristic &ch, m_leService->characteristics()) {
        if (QBluetoothUuid(_serviceUuidTx) == ch.uuid()) {
            writeCharacteristic = ch;
            break;
        }
    }

    if (writeCharacteristic.isValid()) {
        QByteArray dataPart(m_dataForSend.mid(m_sendPos, _sendSizeLimit));
        if (dataPart.isEmpty()) return false;
        m_sendPos += dataPart.size();
        m_leService->writeCharacteristic(writeCharacteristic,
                                         dataPart);
        qDebug() << QDateTime::currentMSecsSinceEpoch();
        return true;
    } else {
        qWarning() << "ERROR: Data write to Bluetooth Low Energy";
    }
    return false;
}

void VSQNetifBLE::onCharacteristicWritten() {
    sendPartOfData();
}

bool VSQNetifBLE::isActive() const {
    return !m_leController.isNull() && !m_leService.isNull() && m_canCommunicate;
}

QAbstractSocket::SocketState
VSQNetifBLE::connectionState() const {
    return isActive() ? QAbstractSocket::ConnectedState : QAbstractSocket::UnconnectedState;
}
