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

/*! \file VSQNetifBase.h
 * \brief Base class for network interface implementation for Virgil IoT Kit Framework
 *
 * #VSQNetifBase provides interface for network interfaces implementation and uses Qt signals. You can use
 * #VSQUdpBroadcast if you do not plan to implement your own interface.
 *
 * #VSQNetifBase has virtual members listed below :
 * - #VSQNetifBase::connectionState has to return current connection state.
 * - #VSQNetifBase::init is called during SNAP initialization.
 * - #VSQNetifBase::deinit is called during SNAP destruction.
 * - #VSQNetifBase::tx is called to send binary data.
 * - #VSQNetifBase::macAddr has to return current MAC address.
 *
 * #VSQNetifBase has Qt signals :
 * - #VSQNetifBase::fireStateChanged has to be emitted when state has been changed.
 * - #VSQNetifBase::fireNewPacket has to be emitted with new received packet.
 *
 * As an example of its implementation you can analyze #VSQUdpBroadcast class.
 */

#ifndef VIRGIL_IOTKIT_QT_VSQNETIFBASE_H
#define VIRGIL_IOTKIT_QT_VSQNETIFBASE_H

#include <QObject>
#include <QAbstractSocket>
#include <virgil/iot/qt/helpers/VSQMac.h>

#include <virgil/iot/protocols/snap.h>

/** SNAP protocol packet */
struct VSQSnapPacket {
    /** Destination's MAC address */
    VSQMac m_dest;

    /** Source's MAC address */
    VSQMac m_src;

    /** Ethernet's packet type */
    uint16_t m_ethernetPacketType;

    /** Transaction's ID */
    VirgilIoTKit::vs_snap_transaction_id_t m_transactionId;

    /** Service's ID */
    VirgilIoTKit::vs_snap_service_id_t m_serviceId;

    /** Element's ID */
    VirgilIoTKit::vs_snap_element_t m_elementId;

    /** Packet's flags */
    uint32_t m_flags;

    /** Packet's content */
    QByteArray m_content;

    /** Timestamp */
    QDateTime m_timestamp;
};

/** SNAP network interface base class */
class VSQNetifBase : public QObject {
    Q_OBJECT

public:
    /** Default constructor */
    VSQNetifBase();
    VSQNetifBase(VSQNetifBase const &) = delete;
    VSQNetifBase &
    operator=(VSQNetifBase const &) = delete;

    virtual ~VSQNetifBase() = default;

    /** Get current connection status
     *
     * \warning You have to implement this function in a child class
     *
     * \return Current connection status
     */
    virtual QAbstractSocket::SocketState
    connectionState() const = 0;

    /** Get network interface
     *
     * \return #vs_netif_t network interface
     */
    VirgilIoTKit::vs_netif_t *
    lowLevelNetif() {
        return &m_lowLevelNetif;
    }

signals:
    /** Signal "State has been changed"
     *
     * \param connectionState Current connection state
     */
    void
    fireStateChanged(QAbstractSocket::SocketState connectionState);

    /** Signal "New packet has been received"
     *
     * \param packet New packet
     */
    void
    fireNewPacket(VSQSnapPacket packet);

protected:
    /** Initialize network interface
     *
     * \warning You have to implement this function in a child class
     *
     * \return true in case of success
     */
    virtual bool
    init() = 0;

    /** Destruct network interface
     *
     * \warning You have to implement this function in a child class
     *
     * \return true in case of success
     */
    virtual bool
    deinit() = 0;

    /** Send binary data
     *
     * \warning You have to implement this function in a child class
     *
     * \param data Data to send
     *
     * \return true in case of success
     */
    virtual bool
    tx(const QByteArray &data) = 0;

    /** Get current MAC address
     *
     * \warning You have to implement this function in a child class
     *
     * \return Current MAC address
     */
    virtual QString
    macAddr() const = 0;

    /** Process packet data
     *
     * \param data Incoming data
     *
     * \return true if data was processed successfully
     */
    bool
    processData(const QByteArray &data);

    // This method is required very seldom. Only in case of re-initialization of network interface
    // outside of init function
    void resetPacketForced();

private:
    static VirgilIoTKit::vs_status_e
    initCb(struct VirgilIoTKit::vs_netif_t *netif,
           const VirgilIoTKit::vs_netif_rx_cb_t rx_cb,
           const VirgilIoTKit::vs_netif_process_cb_t process_cb);
    static VirgilIoTKit::vs_status_e
    deinitCb(struct VirgilIoTKit::vs_netif_t *netif);
    static VirgilIoTKit::vs_status_e
    txCb(struct VirgilIoTKit::vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);
    static VirgilIoTKit::vs_status_e
    macAddrCb(const struct VirgilIoTKit::vs_netif_t *netif, struct VirgilIoTKit::vs_mac_addr_t *mac_addr);

    VirgilIoTKit::vs_netif_t m_lowLevelNetif;
    VirgilIoTKit::vs_netif_rx_cb_t m_lowLevelRxCall = nullptr;
    VirgilIoTKit::vs_netif_process_cb_t m_lowLevelPacketProcess = nullptr;
};

#endif // VIRGIL_IOTKIT_QT_VSQNETIFBASE_H
