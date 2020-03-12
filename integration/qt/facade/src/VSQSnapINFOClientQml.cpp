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

VSQSnapInfoClientQml::VSQSnapInfoClientQml() {
    QObject::connect(&VSQSnapInfoClient::instance(),
                     &VSQSnapInfoClient::fireNewDevice,
                     this,
                     &VSQSnapInfoClientQml::onNewDevice);
    QObject::connect(&VSQSnapInfoClient::instance(),
                     &VSQSnapInfoClient::fireDeviceInfo,
                     this,
                     &VSQSnapInfoClientQml::onDeviceInfo);
}

void
VSQSnapInfoClientQml::onNewDevice(const VSQDeviceInfo deviceInfo) {
    (void)deviceInfo;
    beginInsertRows(QModelIndex(), rowCount() - 1, rowCount() - 1);
    endInsertRows();

    // Full update
    beginResetModel();
    endResetModel();
}

void
VSQSnapInfoClientQml::onDeviceInfo(const VSQDeviceInfo deviceInfo) {
    const auto &devices = devicesList();

    for (int pos = 0; pos < devices.size(); ++pos) {
        const auto &device = devices[pos];

        if (!(device.m_mac == deviceInfo.m_mac)) {
            continue;
        }

        auto idx = index(pos, 0);
        emit dataChanged(idx, idx);

        return;
    }

    Q_ASSERT(false && "Normally unreachable code");
}

int
VSQSnapInfoClientQml::rowCount(const QModelIndex &parent) const {
    Q_UNUSED(parent);
    return devicesList().size();
}

QVariant
VSQSnapInfoClientQml::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= devicesList().size())
        return QVariant();

    const VSQDeviceInfo &deviceInfo = devicesList()[index.row()];
    switch (role) {
    case MacAddress:
        return deviceInfo.m_mac.description();
    case DeviceRoles:
        return deviceInfo.m_deviceRoles.description("\n");
    case ManufactureId:
        return deviceInfo.m_manufactureId.description();
    case DeviceType:
        return deviceInfo.m_deviceType.description();
    case FwVer:
        return deviceInfo.m_fwVer.description();
    case TlVer:
        return deviceInfo.m_tlVer.description();
    case Sent:
        return deviceInfo.m_sent;
    case Received:
        return deviceInfo.m_received;
    case LastTimestamp:
        return deviceInfo.m_lastTimestamp.toString("hh:mm:ss");
    case IsActive:
        return deviceInfo.m_isActive;
    case HasGeneralInfo:
        return deviceInfo.m_hasGeneralInfo;
    case HasStatistics:
        return deviceInfo.m_hasStatistics;

    default:
        Q_ASSERT(false);
        return QString("Unsupported");
    }
}

QHash<int, QByteArray>
VSQSnapInfoClientQml::roleNames() const {
    static const QHash<int, QByteArray> roles{{MacAddress, "macAddress"},
                                              {DeviceRoles, "deviceRoles"},
                                              {ManufactureId, "manufactureId"},
                                              {DeviceType, "deviceType"},
                                              {FwVer, "fwVer"},
                                              {TlVer, "tlVer"},
                                              {Sent, "sent"},
                                              {Received, "received"},
                                              {LastTimestamp, "lastTimestamp"},
                                              {IsActive, "isActive"},
                                              {HasGeneralInfo, "hasGeneralInfo"},
                                              {HasStatistics, "hasStatistics"}};

    return roles;
}
