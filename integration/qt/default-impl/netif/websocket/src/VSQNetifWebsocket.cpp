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

#include <QJsonObject>

#include <virgil/iot/qt/VSQIoTKit.h>
#include <virgil/iot/qt/netif/VSQNetifWebsocket.h>

const QString VSQNetifWebsocket::_accountIdTag("account_id");
const QString VSQNetifWebsocket::_payloadTag("payload");

//******************************************************************************
VSQNetifWebsocket::VSQNetifWebsocket(const QUrl &url, const QString &account) :
    m_canCommunicate(false), m_url(url), m_account(account) {
    connect(&m_webSocket, &QWebSocket::connected, this, &VSQNetifWebsocket::onConnected);
    connect(&m_webSocket, &QWebSocket::disconnected, this, &VSQNetifWebsocket::onDisconnected);
    connect(&m_webSocket, &QWebSocket::stateChanged, this, &VSQNetifWebsocket::onStateChanged);
    connect(&m_webSocket, &QWebSocket::textMessageReceived,this, &VSQNetifWebsocket::onMessageReceived);
    connect(&m_webSocket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(onError(QAbstractSocket::SocketError)));
}

//******************************************************************************
VSQNetifWebsocket::~VSQNetifWebsocket() {
    m_canCommunicate = false;
    m_webSocket.close();
}

//******************************************************************************
bool
VSQNetifWebsocket::init() {
    // TODO: Fix it
    m_mac = VSQMac("01:02:03:04:05:06");
    m_canCommunicate = true;
    m_webSocket.open(m_url);
    return true;
}

//******************************************************************************
bool
VSQNetifWebsocket::deinit() {
    m_canCommunicate = false;
    return true;
}

//******************************************************************************
bool
VSQNetifWebsocket::tx(const QByteArray &data) {
    if (!isActive()) return false;

    qDebug() << "Send data lenght : " << data.size();

    QJsonObject json;
    json[_accountIdTag] = m_account;
    json[_payloadTag] = QString(data.toBase64());


    m_webSocket.sendBinaryMessage(QJsonDocument(json).toJson());

    return true;
}

//******************************************************************************
QString
VSQNetifWebsocket::macAddr() const {

    return m_mac;
}

//******************************************************************************
void VSQNetifWebsocket::registerReceiver() {
    tx(QByteArray());
}

//******************************************************************************
void
VSQNetifWebsocket::onStateChanged(QAbstractSocket::SocketState state) {
    qDebug() << "VSQNetifWebsocket::onStateChanged : " << state;
}

//******************************************************************************
void
VSQNetifWebsocket::onError(QAbstractSocket::SocketError error) {
    qDebug() << "VSQNetifWebsocket::onError : " << error;
}

//******************************************************************************
void
VSQNetifWebsocket::onConnected() {
    VS_LOG_DEBUG("WebSocket connected");
    registerReceiver();

    emit fireStateChanged(m_webSocket.state());
}

//******************************************************************************
void
VSQNetifWebsocket::onDisconnected() {
    VS_LOG_DEBUG("WebSocket disconnected");
    m_webSocket.open(m_url);

    emit fireStateChanged(m_webSocket.state());
}

//******************************************************************************
void
VSQNetifWebsocket::onMessageReceived(QString message) {
    qDebug() << "Message received:" << message;

    if (isActive()) {
        QJsonDocument jsonResponse = QJsonDocument::fromJson(message.toUtf8());
        QJsonObject jsonObject = jsonResponse.object();
        QByteArray dataBase64 = QByteArray::fromStdString((jsonObject[_payloadTag].toString().toStdString()));
        QByteArray data = QByteArray::fromBase64(dataBase64);
        processData(data);
    }
}

//******************************************************************************
bool
VSQNetifWebsocket::isActive() const {
    return QAbstractSocket::ConnectedState == m_webSocket.state() && m_canCommunicate;
}

//******************************************************************************
QAbstractSocket::SocketState
VSQNetifWebsocket::connectionState() const {
    return m_webSocket.state();
}

//******************************************************************************
