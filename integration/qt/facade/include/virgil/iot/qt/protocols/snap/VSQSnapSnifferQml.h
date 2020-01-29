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

/*! \file VSQSnapSnifferQml.h
 * \brief SNAP protocol sniffer with QML abilities
 *
 * #VSQSnapSnifferQml allows to analyse SNAP traffic and to output its state to a QML based application.
 * It receives #VSQNetifBase implementation and uses its #VSQNetifBase::fireStateChanged and
 * #VSQNetifBase::fireNewPacket signals to output current state to a ListView QML control. #VSQSnapSnifferQmlConfig
 * is used to configure #VSQSnapSnifferQml .
 *
 * \note Visit <a href="https://github.com/VirgilSecurity/demo-iotkit-qt">Demo IoTKIT Qt</a> for this class usage
 * example
 *
 * To use it you need configure #VSQIoTKitFacade :
 * - set #VSQFeatures::SNAP_SNIFFER feature.
 * - send #VSQSnapSnifferQmlConfig configuration to #VSQAppConfig
 * - provide #VSQNetifBase implementation. You can use #VSQUdpBroadcast :
 *
 * \code
    auto features = VSQFeatures() << VSQFeatures::SNAP_SNIFFER;                     // SNAP sniffer feature
    auto impl = VSQImplementations() << QSharedPointer<VSQUdpBroadcast>::create();  // VSQNetifBase implementation
    auto appConfig = VSQAppConfig() << VSQSnapSnifferQmlConfig();                   // Configuration

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
        return -1;
    }

 * \endcode
 *
 * To use it as QML model you can set QML context property :
 *
 * \code

    QQmlApplicationEngine engine;                   // QML engine
    QQmlContext *context = engine.rootContext();    // Get root context
    context->setContextProperty("SnapSniffer",
        VSQIoTKitFacade::instance().snapSniffer().get());  // Get sniffer instance and set it as "SnapSniffer" QML data
model

 * \endcode
 *
 * After such initialization use SnapSniffer as ListView data model. Use #VSQSnapSnifferQml::DeviceInfoRoles to obtain
 * needed information roles :
 *
 * \code

ListView {
    model: SnapSniffer
    delegate: Item
    {

        Text {
            text: timestamp + " : " + macSrc + " ==> " + macDst
        }

        Text {
            text: serviceId + " : " + elementId
        }

        Text {
            text: content
        }
    }
}

 * \endcode
 */

#ifndef _VIRGIL_IOTKIT_QT_SNAP_SNIFFER_QML_H_
#define _VIRGIL_IOTKIT_QT_SNAP_SNIFFER_QML_H_

#include <QtQml>

#include <virgil/iot/qt/protocols/snap/VSQNetifBase.h>

/** VSQSnapSnifferQml configurator
 *
 * Add it to the #VSQAppConfig application configuration and call #VSQIoTKitFacade::init function
 */
class VSQSnapSnifferQmlConfig {
public:
    /** Default constructor
     *
     * \param maxLogLines Maximum log lines in ListView item. Older will be deleted with each new line
     */
    VSQSnapSnifferQmlConfig(int maxLogLines = 20) : m_maxLogLines(maxLogLines) {
    }

    /** Maximum log lines */
    int
    maxLogLines() const {
        return m_maxLogLines;
    }

private:
    int m_maxLogLines;
};

/** SNAP Sniffer as ListView data model
 *
 * \note You do not need to call it directly. #VSQIoTKitFacade::init will call it if you provide
 * #VSQFeatures::SNAP_SNIFFER feature
 */
class VSQSnapSnifferQml final : public QAbstractListModel {
    Q_OBJECT

public:
    /** Constructor
     *
     * \param snifferConfig Sniffer configuration
     * \param netif Network interface implementation
     */
    VSQSnapSnifferQml(const VSQSnapSnifferQmlConfig &snifferConfig, VSQNetifBase *netif);
    ~VSQSnapSnifferQml() = default;

    /** Data roles */
    enum DeviceInfoRoles {
        MacDst = Qt::UserRole +
                 1,         /**< Destination's MAC address. #VSQSnapPacket::m_dest field. Use it as "macDst" in QML */
        MacSrc,             /**< Source's MAC address. #VSQSnapPacket::m_src field. Use it as "macSrc" in QML */
        EthernetPacketType, /**< Hex string representation of Ethernet's packet type.
                               #VSQSnapPacket::m_ethernetPacketType field. Use it as "ethernetPacketType" in QML */
        TransactionId, /**< Transaction's ID. #VSQSnapPacket::m_transactionId field. Use it as "transactionId" in QML */
        ServiceId,     /**< Hex string representation of service's ID. #VSQSnapPacket::m_serviceId field. Use it as
                          "serviceId" in QML */
        ElementId,     /**< Hex string representation of element's ID. #VSQSnapPacket::m_elementId field. Use it as
                          "elementId" in QML */
        Flags, /**< Hex string representation of packet's flags. #VSQSnapPacket::m_flags field. Use it as "flags" in QML
                */
        Content,     /**< Packet's content. #VSQSnapPacket::m_content field. Use it as "content" in QML */
        ContentSize, /**< Packet's content size. #VSQSnapPacket::m_content field data size. Use it as "contentSize" in
                        QML */
        Timestamp    /**< Timestamp. #VSQSnapPacket::m_timestamp field. Use it as "timestamp" in QML */
    };

    /** Rows count
     *
     * Returns the number of rows under the given \a parent. When the parent is valid it means that rowCount is
     * returning the number of children of parent.
     *
     * \param parent Parent
     * \return Number of rows
     */
    int
    rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /** Obtain data
     *
     * Returns the data stored under the given \a role for the item referred to by the \a index.
     *
     * \param index Data index
     * \param role #DeviceInfoRoles data role
     * \return
     */
    QVariant
    data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /** Role names
     *
     * Returns the model's role names.
     * \return #DeviceInfoRoles to string conversions as QHash
     */
    QHash<int, QByteArray>
    roleNames() const override;

private:
    using TPackets = QLinkedList<VSQSnapPacket>;

    TPackets m_packets;
    const int m_maxPacketsAmount;

private slots:
    void
    onNewPacket(VSQSnapPacket packet);
};

#endif // _VIRGIL_IOTKIT_QT_SNAP_SNIFFER_QML_H_
