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

#ifndef VIRGIL_IOTKIT_QT_Websocket_H_
#define VIRGIL_IOTKIT_QT_Websocket_H_

#include <QtCore>
#include <QtNetwork>
#include <QtBluetooth>
#include <QtWebSockets>

#include <virgil/iot/qt/protocols/snap/VSQNetifBase.h>

class VSQNetifWebsocket final : public VSQNetifBase {
    Q_OBJECT

public:
    VSQNetifWebsocket(const QUrl &url, const QString &account);

    VSQNetifWebsocket(VSQNetifWebsocket const &) = delete;

    VSQNetifWebsocket &
    operator=(VSQNetifWebsocket const &) = delete;

    virtual ~VSQNetifWebsocket() override;

    QAbstractSocket::SocketState
    connectionState() const override;

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
    void onConnected();
    void onDisconnected();
    void onStateChanged(QAbstractSocket::SocketState state);
    void onError(QAbstractSocket::SocketError error);
    void onMessageReceived(QString message);

private:
    VSQMac m_mac;

    bool m_canCommunicate;                                  /**< shows communication state */

    QWebSocket m_webSocket;
    QUrl m_url;
    QString m_account;

    static const QString _accountIdTag;
    static const QString _payloadTag;

    /**
     * @brief Check is net connection is active
     * @return "true" is active
     */
    virtual bool isActive() const;


    void registerReceiver();
};

#endif // VIRGIL_IOTKIT_QT_BLE_H_

