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

#include <virgil/iot/qt/VSQIoTKit.h>

using namespace VirgilIoTKit;

/* Send log message about new active device */
//#define LOG_START_NOTIFY

/* Send log message about general information device changes */
//#define LOG_GENERAL_INFO

/* Send log message about new device statistics */
//#define LOG_STATISTICS

/* Send log message about dead device */
//#define LOG_DEAD_DEVICE

VSQSnapInfoClient::VSQSnapInfoClient() {
    m_snapInfoImpl.device_start = startNotify;
    m_snapInfoImpl.general_info = generalInfo;
    m_snapInfoImpl.statistics = statistics;

    m_snapService = vs_snap_info_client(m_snapInfoImpl);

    constexpr auto deadDevicesCheckMSec = 1000;
    m_deviceAliveTimer = startTimer(deadDevicesCheckMSec, Qt::VeryCoarseTimer);
    if (!m_deviceAliveTimer) {
        VS_LOG_WARNING("Unable to start timer for alive device check for INFO Client");
    }
}

vs_status_e
VSQSnapInfoClient::startNotify(vs_snap_info_device_t *deviceRaw) {
    VSQDeviceInfo &device = instance().getDevice(deviceRaw->mac);

    device.m_hasGeneralInfo = false;
    device.m_hasStatistics = false;
    device.m_isActive = true;
    device.m_lastTimestamp = QDateTime::currentDateTime();

#if defined(LOG_START_NOTIFY)
    VS_LOG_INFO("New device : MAC %s", VSQCString(device.m_mac.description()));
#endif

    emit instance().fireDeviceInfo(device);

    if (!instance().onStartFullPolling(device.m_mac)) {
        VS_LOG_CRITICAL("Unable to start polling for device %s", VSQCString(device.m_mac.description()));
        return VS_CODE_ERR_POLLING_INFO_CLIENT;
    }

    return VS_CODE_OK;
}

vs_status_e
VSQSnapInfoClient::generalInfo(vs_info_general_t *generalData) {
    VSQDeviceInfo &device = instance().getDevice(generalData->default_netif_mac);
    bool changed = false;

    auto copyAndCheck = [&changed](auto &dst, const auto &src) {
        changed = !dst.equal(src);
        dst = src;
    };

    copyAndCheck(device.m_manufactureId, generalData->manufacture_id);
    copyAndCheck(device.m_deviceType, generalData->device_type);
    copyAndCheck(device.m_deviceRoles, generalData->device_roles);
    copyAndCheck(device.m_fwVer, generalData->fw_ver);
    copyAndCheck(device.m_tlVer, generalData->tl_ver);

#if defined(LOG_GENERAL_INFO)
    if (changed) {
        VS_LOG_DEBUG(
                "Device general info : MAC %s, manufacture ID \"%s\", device type \"%s\", device role(s) \"%s\", "
                "Firmware version \"%s\", TrustList version \"%s\"",
                VSQCString(device.m_mac.description()),
                VSQCString(device.m_manufactureId.description()),
                VSQCString(device.m_deviceType.description()),
                VSQCString(device.m_deviceRoles.description()),
                VSQCString(device.m_fwVer.description()),
                VSQCString(device.m_tlVer.description()));
    }
#else
    (void)changed;
#endif

    device.m_isActive = true;
    device.m_hasGeneralInfo = true;
    device.m_lastTimestamp = QDateTime::currentDateTime();

    emit instance().fireDeviceInfo(device);

    return VS_CODE_OK;
}

vs_status_e
VSQSnapInfoClient::statistics(vs_info_statistics_t *statistics) {
    VSQDeviceInfo &device = instance().getDevice(statistics->default_netif_mac);

    device.m_sent = statistics->sent;
    device.m_received = statistics->received;

    device.m_isActive = true;
    device.m_hasStatistics = true;
    device.m_lastTimestamp = QDateTime::currentDateTime();

#if defined(LOG_STATISTICS)
    VS_LOG_DEBUG("Device statistics : MAC %s, sent %d, received %d",
                 VSQCString(device.m_mac.description()),
                 device.m_sent,
                 device.m_received);
#endif

    emit instance().fireDeviceInfo(device);

    return VS_CODE_OK;
}

bool
VSQSnapInfoClient::changePolling(std::initializer_list<EPolling> pollingOptions,
                                 const VSQMac &deviceMac,
                                 bool enable,
                                 quint16 periodSeconds) {
    vs_mac_addr_t mac = deviceMac;
    uint32_t pollingElements = 0;

    for (auto pollingOption : pollingOptions) {
        pollingElements |= pollingOption;
    }

    if (vs_snap_info_set_polling(vs_snap_netif_routing(), &mac, pollingElements, enable, periodSeconds) != VS_CODE_OK) {
        VS_LOG_ERROR("Unable to setup info polling");
        return false;
    }

    for (auto &device : m_devicesInfo) {
        if (deviceMac == broadcastMac || device.m_mac == deviceMac) {
            device.m_pollingInterval = periodSeconds;
        }
    }
    return true;
}

VSQDeviceInfo &
VSQSnapInfoClient::getDevice(const VSQMac &mac) {
    VSQDeviceInfo *device = nullptr;

    for (auto &curDevice : m_devicesInfo) {
        if (curDevice.m_mac == mac) {
            device = &curDevice;
            break;
        }
    }

    if (!device) {
        m_devicesInfo.push_back(VSQDeviceInfo(mac));
        device = &m_devicesInfo.last();
        emit fireNewDevice(*device);
    }

    return *device;
}

void
VSQSnapInfoClient::timerEvent(QTimerEvent *event) {
    if (event->timerId() == m_deviceAliveTimer) {
        auto currentTime = QDateTime::currentDateTime();

        for (auto &device : m_devicesInfo) {
            if (!device.m_isActive) {
                continue;
            }

            constexpr auto deadDelayPollingIntervals = 3;
            constexpr auto SecToMSec = 1000;

            auto deadDelayMSec = device.m_pollingInterval * deadDelayPollingIntervals * SecToMSec;

            if (device.m_lastTimestamp.msecsTo(currentTime) > deadDelayMSec) {

#if defined(LOG_DEAD_DEVICE)
                VS_LOG_INFO("Dead device : MAC %s", VSQCString(device.m_mac.description()));
#endif
                device.m_isActive = false;
                emit fireDeviceInfo(device);
            }
        }
    }
}
