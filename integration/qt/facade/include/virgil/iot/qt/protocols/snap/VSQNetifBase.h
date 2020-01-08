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

#ifndef VIRGIL_IOTKIT_QT_VSQNETIFBASE_H
#define VIRGIL_IOTKIT_QT_VSQNETIFBASE_H

#include <QObject>
#include <QAbstractSocket>
#include <virgil/iot/qt/helpers/VSQMac.h>

#include <virgil/iot/protocols/snap.h>

struct VSQSnapPacket {
    VSQMac m_dest;
    VSQMac m_src;
    uint16_t m_ethernetPacketType;
    VirgilIoTKit::vs_snap_transaction_id_t m_transactionId;
    VirgilIoTKit::vs_snap_service_id_t m_serviceId;
    VirgilIoTKit::vs_snap_element_t m_elementId;
    uint32_t m_flags;
    QByteArray m_content;
    QDateTime m_timestamp;
};

class VSQNetifBase: public QObject {
    Q_OBJECT

public:
    VSQNetifBase();
    VSQNetifBase(VSQNetifBase const &) = delete;
    VSQNetifBase &operator=(VSQNetifBase const &) = delete;

    virtual ~VSQNetifBase() = default;
    virtual QAbstractSocket::SocketState connectionState() const  = 0;

    operator VirgilIoTKit::vs_netif_t *()   { return &m_lowLevelNetif; }

signals:
    void fireStateChanged(QAbstractSocket::SocketState connectionState);
    void fireNewPacket(VSQSnapPacket packet);

protected:
    virtual bool init() = 0;
    virtual bool deinit() = 0;
    virtual bool tx(const QByteArray &data) = 0;
    virtual QString macAddr() const = 0;

    // This method must be called by implementation of network interface.
    // It uses low level callbacks and sends data using signals
    bool processData(const QByteArray &data);

    // This method is required very seldom. Only in case of re-initialization of network interface
    // outside of init function
    void resetPacketForced();

private:
    static VirgilIoTKit::vs_status_e initCb(struct VirgilIoTKit::vs_netif_t *netif,
                                            const VirgilIoTKit::vs_netif_rx_cb_t rx_cb,
                                            const VirgilIoTKit::vs_netif_process_cb_t process_cb);
    static VirgilIoTKit::vs_status_e deinitCb(const struct VirgilIoTKit::vs_netif_t *netif);
    static VirgilIoTKit::vs_status_e txCb(const struct VirgilIoTKit::vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);
    static VirgilIoTKit::vs_status_e macAddrCb(const struct VirgilIoTKit::vs_netif_t *netif, struct VirgilIoTKit::vs_mac_addr_t *mac_addr);

    VirgilIoTKit::vs_netif_t m_lowLevelNetif;
    VirgilIoTKit::vs_netif_rx_cb_t m_lowLevelRxCall = nullptr;
    VirgilIoTKit::vs_netif_process_cb_t m_lowLevelPacketProcess = nullptr;
};

#endif //VIRGIL_IOTKIT_QT_VSQNETIFBASE_H
