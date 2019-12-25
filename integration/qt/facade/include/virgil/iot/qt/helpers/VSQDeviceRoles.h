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

#ifndef VIRGIL_IOTKIT_QT_DEVICE_ROLES_H
#define VIRGIL_IOTKIT_QT_DEVICE_ROLES_H

#include <QtCore>
#include <virgil/iot/protocols/snap/snap-structs.h>

class VSQDeviceRoles {
public:
    using TRolesList = std::initializer_list<VirgilIoTKit::vs_snap_device_role_e>;

    VSQDeviceRoles() = default;
    VSQDeviceRoles(uint32_t roles);

    VSQDeviceRoles &
    operator<<(VirgilIoTKit::vs_snap_device_role_e role) {
        m_deviceRoles << role;
        return *this;
    }

    QString
    description(const QString &divider = QString(", ")) const;

    operator QString() const {
        return description();
    }
    operator uint32_t() const;

    bool
    hasRole(VirgilIoTKit::vs_snap_device_role_e role) const {
        return m_deviceRoles.contains(role);
    }
    bool
    hasRoles(TRolesList roles) const;

private:
    QSet<VirgilIoTKit::vs_snap_device_role_e> m_deviceRoles;
};


#endif // VIRGIL_IOTKIT_QT_DEVICE_ROLES_H
