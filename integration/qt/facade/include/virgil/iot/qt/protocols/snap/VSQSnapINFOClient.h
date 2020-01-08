//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

struct VSQDeviceInfo {
    VSQDeviceInfo()
        : m_pollingInterval(1), m_sent(0), m_received(0), m_isActive(false), m_hasGeneralInfo(false),
          m_hasStatistics(false) {
    }

    VSQDeviceInfo(const VSQMac &mac)
        : VSQDeviceInfo() {
            m_mac = mac;
    }

    quint16 m_pollingInterval;
    VSQMac m_mac;
    VSQDeviceRoles m_deviceRoles;
    VSQManufactureId m_manufactureId;
    VSQDeviceType m_deviceType;
    VSQFileVersion m_fwVer;
    VSQFileVersion m_tlVer;
    quint32 m_sent;
    quint32 m_received;
    QDateTime m_lastTimestamp;

    bool m_isActive;
    bool m_hasGeneralInfo;
    bool m_hasStatistics;

    bool
    equal(const VSQDeviceInfo &deviceInfo) const;

    bool
    operator==(const VSQDeviceInfo &deviceInfo) const {
        return equal(deviceInfo);
    }

    bool
    operator!=(const VSQDeviceInfo &deviceInfo) const {
        return !equal(deviceInfo);
    }
};

class VSQSnapInfoClient final :
        public QObject,
        public VSQSingleton<VSQSnapInfoClient>,
        public VSQSnapServiceBase {

    Q_OBJECT

    friend VSQSingleton<VSQSnapInfoClient>;

public:
    enum EPolling {
        GENERAL_INFO = VirgilIoTKit::VS_SNAP_INFO_GENERAL,
        STATISTICS = VirgilIoTKit::VS_SNAP_INFO_STATISTICS
    };

    using TEnumDevicesArray = QVector<VSQDeviceInfo>;

    const VirgilIoTKit::vs_snap_service_t *
    serviceInterface() override {
        return m_snapService;
    }

    VSQFeatures::EFeature
    serviceFeature() const override {
        return VSQFeatures::SNAP_INFO_CLIENT;
    }

    const QString &
    serviceName() const override {
        static QString name{"INFO Client"};
        return name;
    }

    bool
    changePolling(std::initializer_list<EPolling> pollingOptions,
                  const VSQMac &deviceMac = broadcastMac,
                  bool enable = true,
                  quint16 periodSeconds = 1);

    bool
    startFullPolling(const VSQMac &deviceMac = broadcastMac, quint16 periodSeconds = 1) {
        return changePolling(
                {VSQSnapInfoClient::GENERAL_INFO, VSQSnapInfoClient::STATISTICS}, deviceMac, true, periodSeconds);
    }

    const TEnumDevicesArray &devicesList() const { return m_devicesInfo; }

signals:
    void
    fireDeviceInfo(const VSQDeviceInfo &deviceInfo);

    void
    fireNewDevice(const VSQDeviceInfo &deviceInfo);

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
