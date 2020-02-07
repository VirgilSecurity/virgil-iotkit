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

/*! \file VSQUdpBroadcast.h
 * \brief UDP broadcast network interface implementation
 *
 * #VSQUdpBroadcast is based on #VSQNetifBase class. It implements SNAP protocol based on UDP broadcast packets. It can
 * be used for any network supporting UDP broadcast messages.
 *
 * You can add #VSQUdpBroadcast class as one of implementations for #VSQIoTKitFacade. Also do not forget to add
 * #VSQFeatures::SNAP_INFO_CLIENT feature :
 *
 * \code

    auto features = VSQFeatures() << VSQFeatures::SNAP_INFO_CLIENT;
    auto impl = VSQImplementations() << QSharedPointer<VSQUdpBroadcast>::create();

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
        return -1;
    }

 * \endcode
 */

#ifndef VIRGIL_IOTKIT_QT_UDP_BROADCAST_H_
#define VIRGIL_IOTKIT_QT_UDP_BROADCAST_H_

#include <QtCore>
#include <QtNetwork>

#include <virgil/iot/qt/protocols/snap/VSQNetifBase.h>

/** UDP Broadcast network interface implementation */
class VSQUdpBroadcast final : public VSQNetifBase {
    Q_OBJECT
public:
    /** Default constructor
     *
     * \param port UDP port. Default port is 4100
     */
    VSQUdpBroadcast(quint16 port = 4100);

    VSQUdpBroadcast(VSQUdpBroadcast const &) = delete;

    VSQUdpBroadcast &
    operator=(VSQUdpBroadcast const &) = delete;

    virtual ~VSQUdpBroadcast() = default;

    /** Get current connection status
     *
     * \warning You have to implement this function in a child class
     *
     * \return Current connection status
     */
    QAbstractSocket::SocketState
    connectionState() const override {
        return m_socket.state();
    }

    void
    restart();

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
    void
    onHasInputData();

private:
    quint16 m_port;
    QUdpSocket m_socket;
    VSQMac m_mac;
};

#endif // VIRGIL_IOTKIT_QT_UDP_BROADCAST_H_
