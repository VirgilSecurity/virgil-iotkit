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

#ifndef VIRGIL_IOTKIT_QT_BLE_H_
#define VIRGIL_IOTKIT_QT_BLE_H_

#include <QtCore>
#include <QtNetwork>
#include <QtBluetooth>

#include <virgil/iot/qt/protocols/snap/VSQNetifBase.h>

class VSQNetifBLE final : public VSQNetifBase {
    Q_OBJECT

public:
    VSQNetifBLE();

    VSQNetifBLE(VSQNetifBLE const &) = delete;

    VSQNetifBLE &
    operator=(VSQNetifBLE const &) = delete;

    virtual ~VSQNetifBLE() = default;

    QAbstractSocket::SocketState
    connectionState() const override;

public slots:
    /**
     * @brief start bluetooth communication
     * @param[in] device - device info for connection
     * @return "true" if communication started correctly
     */
    bool onOpenDevice(const QBluetoothDeviceInfo device);

    void onCloseDevice();

signals:
    void fireDeviceReady();

protected:
    bool
    init() override;

    bool
    deinit() override;

    bool
    tx(const QByteArray &data) override;

    QString
    macAddr() const override;


private slots:
    /**
     * @brief Data for read are presend.
     */
    void onNotification(const QLowEnergyCharacteristic & characteristic, const QByteArray & data);

    /**
     * @brief Called when connection with device established, but services not discovered
     */
    void onDeviceConnected();

    /**
     * @brief Called when connection with device stopped
     */
    void onDeviceDisconnected();

    /**
     * @brief Called when one service discovered
     * @param[in] uuid - identifier of discovered service
     */
    void onServiceDiscovered(QBluetoothUuid uuid);

    /**
     * @brief Called when services discovery complitly finished
     */
    void onServicesDiscoveryFinished();

    /**
     * @brief Called on services discovery error
     * @param[in] error - occured error
     */
    void onServicesDiscoveryError(QLowEnergyController::Error error);

    /**
     * @brief Called on services details discovered
     * @param[in] serviceState - current state of service
     */
    void onServiceDetailsDiscovered(QLowEnergyService::ServiceState serviceState);

private:
    VSQMac m_mac;

    bool m_canCommunicate;                                  /**< shows communication state */
    QSharedPointer <QLowEnergyController> m_leController;   /**< Controller for current device */
    QSharedPointer <QLowEnergyService> m_leService;         /**< Bluetooth low energy service */
    QList <QBluetoothUuid> m_availableServices;             /**< List of available services for current device */

    static const QString _serviceUuid;                      /**< Bluetooth low energy service common */
    static const QString _serviceUuidTx;                    /**< uuid for transmit bluetooth service of our devices */
    static const QString _serviceUuidRx;                    /**< uuid for transmit bluetooth service of our devices */
    static const size_t _sendSizeLimit;                     /**< Limit for data send per one package (in bytes) */

    /**
     * @brief Set slot for notifications receive
     */
    bool prepareNotificationReceiver();

    /**
     * @brief Check is net connection is active
     * @return "true" is active
     */
    virtual bool isActive() const;

    /**
     * @brief Terminate net conection
     */
    virtual void deactivate();
};

#endif // VIRGIL_IOTKIT_QT_BLE_H_

