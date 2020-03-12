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

/*! \file VSQSnapINFOClient.h
 * \brief SNAP protocol's INFO client service implementation
 *
 * #VSQSnapInfoClient implements INFO client service that receives information about active devices.
 *
 * To use it specify #VSQFeatures::SNAP_INFO_CLIENT feature during #VSQIoTKitFacade initialization :
 *
 * \code

    auto features = VSQFeatures() << VSQFeatures::SNAP_INFO_CLIENT;

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
        return -1;
    }

 * \endcode
 *
 * This class uses Qt signals that notifies application about new information :
 * - #VSQSnapInfoClient::fireNewDevice is emitted when new device has been activated
 * - #VSQSnapInfoClient::fireDeviceInfo is emitted when new information has been received
 */

#ifndef _VIRGIL_IOTKIT_QT_SNAP_INFO_CLIENT_SERVICE_H_
#define _VIRGIL_IOTKIT_QT_SNAP_INFO_CLIENT_SERVICE_H_

#include <QtCore>

#include <virgil/iot/protocols/snap/info/info-structs.h>
#include <virgil/iot/protocols/snap/info/info-client.h>
#include <virgil/iot/qt/helpers/VSQMac.h>
#include <virgil/iot/qt/helpers/VSQDeviceRoles.h>
#include <virgil/iot/qt/helpers/VSQManufactureId.h>
#include <virgil/iot/qt/helpers/VSQDeviceType.h>
#include <virgil/iot/qt/helpers/VSQFileVersion.h>
#include <virgil/iot/qt/helpers/VSQSingleton.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapServiceBase.h>

/** Device information
 *
 * This structure is used by #VSQSnapInfoClient class
 */
struct VSQDeviceInfo {

    /** Default constructor */
    VSQDeviceInfo()
        : m_pollingInterval(1), m_sent(0), m_received(0), m_isActive(false), m_hasGeneralInfo(false),
          m_hasStatistics(false) {
    }

    /** Copy constructor */
    VSQDeviceInfo(const VSQMac &mac) : VSQDeviceInfo() {
        m_mac = mac;
    }

    /** Polling interval in seconds */
    quint16 m_pollingInterval;

    /** MAC address */
    VSQMac m_mac;

    /** Device roles */
    VSQDeviceRoles m_deviceRoles;

    /** Manufacture ID */
    VSQManufactureId m_manufactureId;

    /** Device type */
    VSQDeviceType m_deviceType;

    /** File version */
    VSQFileVersion m_fwVer;

    /** Trust List version */
    VSQFileVersion m_tlVer;

    /** Sent packets */
    quint32 m_sent;

    /** Received packets */
    quint32 m_received;

    /** Last information timestamp */
    QDateTime m_lastTimestamp;

    /** Device is active */
    bool m_isActive;

    /** Device has general information */
    bool m_hasGeneralInfo;

    /** Device has statistics */
    bool m_hasStatistics;
};

/** SNAP protocol's INFO Client implementation
 *
 * Use #VSQIoTKitFacade::init to initialize this class
 */
class VSQSnapInfoClient final : public QObject, public VSQSingleton<VSQSnapInfoClient>, public VSQSnapServiceBase {

    Q_OBJECT

    friend VSQSingleton<VSQSnapInfoClient>;

public:
    /** Polling elements */
    enum EPolling {
        GENERAL_INFO = VirgilIoTKit::VS_SNAP_INFO_GENERAL, /**< General information */
        STATISTICS = VirgilIoTKit::VS_SNAP_INFO_STATISTICS /**< Statistics information */
    };

    /** "Devices list" data type */
    using TEnumDevicesArray = QVector<VSQDeviceInfo>;

    /** Get service interface
     *
     * \return Service interface
     */
    const VirgilIoTKit::vs_snap_service_t *
    serviceInterface() override {
        return m_snapService;
    }

    /** Get service feature
     *
     * \return Service feature
     */
    VSQFeatures::EFeature
    serviceFeature() const override {
        return VSQFeatures::SNAP_INFO_CLIENT;
    }

    /** Get service name
     *
     * \return Service name
     */
    const QString &
    serviceName() const override {
        static QString name{"INFO Client"};
        return name;
    }

    /** Change device's polling state
     *
     * \param pollingOptions Polling options list
     * \param deviceMac Device's MAC address. #broadcastMac is used by default for broadcast polling options
     * \param enable Enable \a pollingOptions. True by default
     * \param periodSeconds Polling period in seconds. 1 second is used by default
     *
     * \return
     */
    bool
    changePolling(std::initializer_list<EPolling> pollingOptions,
                  const VSQMac &deviceMac = broadcastMac,
                  bool enable = true,
                  quint16 periodSeconds = 1);

    /** Get devices list
     *
     * \return Current devices list
     */
    const TEnumDevicesArray &devicesList() const { return m_devicesInfo; }

public slots:
    /** Start full polling
     *
     * \param deviceMac Device's MAC address. #broadcastMac is used by default for broadcast polling options
     * \param periodSeconds Polling period in seconds. 1 second is used by default
     *
     * \return
     */
    bool
    onStartFullPolling(const VSQMac &deviceMac = broadcastMac, quint16 periodSeconds = 1) {
        return changePolling(
                {VSQSnapInfoClient::GENERAL_INFO, VSQSnapInfoClient::STATISTICS}, deviceMac, true, periodSeconds);
    }

signals:

    /** Signal "New information has been received"
     *
     * \param deviceInfo Device information
     */
    void
    fireDeviceInfo(const VSQDeviceInfo deviceInfo);

    /** Signal "New device has been activated"
     *
     * \param deviceInfo Device information
     */
    void
    fireNewDevice(const VSQDeviceInfo deviceInfo);

private:
    const VirgilIoTKit::vs_snap_service_t *m_snapService;
    mutable VirgilIoTKit::vs_snap_info_client_service_t m_snapInfoImpl;
    TEnumDevicesArray m_devicesInfo;
    int m_deviceAliveTimer = 0;

    VSQSnapInfoClient();
    ~VSQSnapInfoClient() = default;

    void
    timerEvent(QTimerEvent *event) override;

    VSQDeviceInfo &
    getDevice(const VSQMac &mac);

    static VirgilIoTKit::vs_status_e
    startNotify(VirgilIoTKit::vs_snap_info_device_t *deviceRaw);

    static VirgilIoTKit::vs_status_e
    generalInfo(VirgilIoTKit::vs_info_general_t *generalData);

    static VirgilIoTKit::vs_status_e
    statistics(VirgilIoTKit::vs_info_statistics_t *statistics);
};

#endif // _VIRGIL_IOTKIT_QT_SNAP_INFO_CLIENT_SERVICE_H_
