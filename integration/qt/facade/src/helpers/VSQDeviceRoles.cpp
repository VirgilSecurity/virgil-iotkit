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

VSQDeviceRoles::VSQDeviceRoles(uint32_t roles) {
    for (uint64_t cur_role = 1; cur_role < std::numeric_limits<uint32_t>::max(); cur_role <<= 1) {
        if (roles & cur_role) {
            m_deviceRoles << static_cast<VirgilIoTKit::vs_snap_device_role_e>(cur_role);
        }
    }
}

bool
VSQDeviceRoles::hasRoles(TRolesList roles) const {
    for (auto role : roles) {
        if (!m_deviceRoles.contains(role)) {
            return false;
        }
    }

    return true;
}

VSQDeviceRoles::operator uint32_t() const {
    uint32_t roles = 0;

    for (auto role : m_deviceRoles)
        roles |= role;

    return roles;
}

QString
VSQDeviceRoles::description(const QString &divider) const {
    static const QMap<VirgilIoTKit::vs_snap_device_role_e, QString> rolesDescription = {
            {VirgilIoTKit::VS_SNAP_DEV_GATEWAY, "Gateway"},
            {VirgilIoTKit::VS_SNAP_DEV_THING, "Thing"},
            {VirgilIoTKit::VS_SNAP_DEV_CONTROL, "Control"},
            {VirgilIoTKit::VS_SNAP_DEV_LOGGER, "Logger"},
            {VirgilIoTKit::VS_SNAP_DEV_SNIFFER, "Sniffer"},
            {VirgilIoTKit::VS_SNAP_DEV_DEBUGGER, "Debugger"},
            {VirgilIoTKit::VS_SNAP_DEV_INITIALIZER, "Initializer"}};
    QString descr;

    bool firstSymbol = true;
    for (auto role : m_deviceRoles) {
        if (firstSymbol) {
            firstSymbol = false;
        } else {
            descr += divider;
        }

        descr += rolesDescription[role];
    }

    return descr;
}
