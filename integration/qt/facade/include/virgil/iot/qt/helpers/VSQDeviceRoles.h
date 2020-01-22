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

/*! \file VSQDeviceRoles.h
 * \brief Virgil IoT Kit Qt device roles
 *
 * #VSQDeviceRoles is the list of device roles.
 *
 * Configure #VSQDeviceRoles by using operator << :
 * \code
    auto roles = VSQDeviceRoles() << VirgilIoTKit::VS_SNAP_DEV_CONTROL;

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
    }
 * \endcode
 *
 * You can output devices roles to the string representation :
 * \code

    VSQDeviceRoles roles;   // Initialized device roles
    QString rolesDescription = roles;

 * \endcode
 *
 */

#ifndef VIRGIL_IOTKIT_QT_DEVICE_ROLES_H
#define VIRGIL_IOTKIT_QT_DEVICE_ROLES_H

#include <QtCore>
#include <virgil/iot/protocols/snap/snap-structs.h>

/** Device roles */
class VSQDeviceRoles {
public:
    /** Device roles list */
    using TRolesList = std::initializer_list<VirgilIoTKit::vs_snap_device_role_e>;

    VSQDeviceRoles() = default;

    /** Assign device roles as bits mask
     *
     * \param roles Device roles #vs_snap_device_role_e bits mask
     */
    VSQDeviceRoles(uint32_t roles);

    /** Add device role
     *
     * \param role Device role
     * \return Reference to the #VSQDeviceRoles instance
     */
    VSQDeviceRoles &
    operator<<(VirgilIoTKit::vs_snap_device_role_e role) {
        m_deviceRoles << role;
        return *this;
    }

    /** Describe device roles
     *
     * Call this function to receive text description. You can set any \a divider divider, for example '\n'
     * to obtain multiline description
     *
     * \param divider Divider string
     * \return Device roles text description
     */
    QString
    description(const QString &divider = QString(", ")) const;

    /** Describe device roles
     *
     * #description function call
     */
    operator QString() const {
        return description();
    }

    /** Get #vs_snap_device_role_e bits mask */
    operator uint32_t() const;

    /** Compare device roles
     *
     * \param deviceRole Device role to be compared with the current one
     * \return true if both device roles are equal
     */
    bool
    equal(const VSQDeviceRoles &deviceRole) const {
        uint32_t first = *this;
        uint32_t second = deviceRole;
        return first == second;
    }

    /** Check device role
     *
     * This function returns true if \a role is present in the device roles list
     *
     * \param role Device role to check
     * \return true if \a role is present
     */
    bool
    hasRole(VirgilIoTKit::vs_snap_device_role_e role) const {
        return m_deviceRoles.contains(role);
    }

    /** Check device roles
     *
     * This function returns true if all roles from the \a roles list are present in the device roles list
     *
     * \param roles Device roles list to check
     * \return true if all \a roles are present
     */
    bool
    hasRoles(TRolesList roles) const;

private:
    QSet<VirgilIoTKit::vs_snap_device_role_e> m_deviceRoles;
};


#endif // VIRGIL_IOTKIT_QT_DEVICE_ROLES_H
