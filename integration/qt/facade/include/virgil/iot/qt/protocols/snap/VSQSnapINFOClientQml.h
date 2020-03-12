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

/*! \file VSQSnapINFOClientQml.h
 * \brief SNAP protocol sniffer with QML abilities
 *
 * #VSQSnapInfoClientQml uses #VSQSnapInfoClient signals to retransmit them to a QML.
 * It receives #VSQNetifBase implementation and uses its #VSQNetifBase::fireStateChanged and
 * #VSQNetifBase::fireNewPacket signals to output current state to a ListView QML control. #VSQSnapSnifferQmlConfig
 * is used to configure #VSQSnapSnifferQml .
 *
 * \note Visit <a href="https://github.com/VirgilSecurity/demo-iotkit-qt">Demo IoTKIT Qt</a> for this class usage
 * example
 *
 * To use it you need to initialize #VSQSnapInfoClient :
 *
 * \code

    auto features = VSQFeatures() << VSQFeatures::SNAP_INFO_CLIENT;

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
    context->setContextProperty("SnapInfoClient",
        &VSQSnapInfoClientQml::instance());  // Get INFO client instance and set it as "SnapInfoClient" QML data model

 * \endcode
 *
 * After such initialization use SnapInfoClient as ListView data model. Use #VSQSnapInfoClientQml::DeviceInfoRoles to
 * obtain needed information :
 *
 * \code

ListView {

    model: SnapInfoClient

    delegate: Item
    {
       Text {
           text: deviceRoles
       }

       Text {
           text: isActive ? "active" : "not active"
       }

       Text {
           text: macAddress
       }

       Text {
           text: "fw " + fwVer + ", tl " + tlVer
       }
   }
}
 * \endcode
 */

#ifndef _VIRGIL_IOTKIT_QT_SNAP_INFO_CLIENT_SERVICE_QML_H_
#define _VIRGIL_IOTKIT_QT_SNAP_INFO_CLIENT_SERVICE_QML_H_

#include <QtQml>

#include <virgil/iot/qt/helpers/VSQSingleton.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapINFOClient.h>

/** INFO Client interface */
class VSQSnapInfoClientQml final : public QAbstractListModel, public VSQSingleton<VSQSnapInfoClientQml> {
    Q_OBJECT

    friend VSQSingleton<VSQSnapInfoClientQml>;

public:
    /** Data roles */
    enum DeviceInfoRoles {
        MacAddress = Qt::UserRole + 1, /**< MAC address. #VSQDeviceInfo::m_mac field. Use it as "macAddress" QML */
        DeviceRoles,   /**< Device roles. #VSQDeviceInfo::m_deviceRoles field. Use it as "deviceRoles" QML */
        ManufactureId, /**< Manufacture ID. #VSQDeviceInfo::m_manufactureId field. Use it as "manufactureId" QML */
        DeviceType,    /**< Device type. #VSQDeviceInfo::m_deviceType field. Use it as "deviceType" QML */
        FwVer,         /**< File version. #VSQDeviceInfo::m_fwVer field. Use it as "fwVer" QML */
        TlVer,         /**< Trust List version. #VSQDeviceInfo::m_tlVer field. Use it as "tlVer" QML */
        Sent,          /**< Sent packets. #VSQDeviceInfo::m_sent field. Use it as "sent" QML */
        Received,      /**< Received packets. #VSQDeviceInfo::m_received field. Use it as "received" QML */
        LastTimestamp, /**< Last information timestamp. #VSQDeviceInfo::m_lastTimestamp field. Use it as "lastTimestamp"
                          QML */
        IsActive,      /**< Device is active. #VSQDeviceInfo::m_isActive field. Use it as "isActive" QML */
        HasGeneralInfo, /**< Device has general informatio. #VSQDeviceInfo::m_hasGeneralInfo field. Use it as
                           "hasGeneralInfo" QML */
        HasStatistics   /**< Device has statistics. #VSQDeviceInfo::m_hasStatistics field. Use it as "hasStatistics" QML
                         */
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
    VSQSnapInfoClientQml();
    ~VSQSnapInfoClientQml() = default;

    static const VSQSnapInfoClient::TEnumDevicesArray &
    devicesList() {
        return VSQSnapInfoClient::instance().devicesList();
    }

private slots:
    void
    onDeviceInfo(const VSQDeviceInfo deviceInfo);

    void
    onNewDevice(const VSQDeviceInfo deviceInfo);
};

#endif // _VIRGIL_IOTKIT_QT_SNAP_INFO_CLIENT_SERVICE_QML_H_
