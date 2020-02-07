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

/*! \file VSQAppConfig.h
 * \brief Virgil IoT Kit Framework configuration
 *
 * #VSQAppConfig is used to set up application configurations parameters prior to #VSQIoTKitFacade::init call.
 *
 * Configure #VSQAppConfig by using operator << :
 * \code
    auto appConfig = VSQAppConfig() << VSQManufactureId() << VSQDeviceType() << VSQDeviceSerial();

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
    }
 * \endcode
 *
 * See \ref VSQIoTKitFacade_usage for Virgil IoT Kit initialization.
 *
 * There are several options to be configured :
 * - #VSQDeviceRoles : device roles
 * - #VSQDeviceSerial : device serial
 * - #VSQDeviceType : device type
 * - #VSQManufactureId : manufacture ID
 * - #VSQSnapSnifferQmlConfig : sniffer configuration. Requires #SNAP_SNIFFER feature
 * - #vs_log_level_t : logging level
 */

#ifndef VIRGIL_IOTKIT_QT_APP_CONFIG_H
#define VIRGIL_IOTKIT_QT_APP_CONFIG_H

#include <virgil/iot/qt/helpers/VSQManufactureId.h>
#include <virgil/iot/qt/helpers/VSQDeviceType.h>
#include <virgil/iot/qt/helpers/VSQDeviceSerial.h>
#include <virgil/iot/qt/helpers/VSQDeviceRoles.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapSnifferQml.h>

/** Application configuration
 *
 * Initialize this class and use it for #VSQIoTKitFacade::init call.
 */
class VSQAppConfig {
public:
    /** Manufacture ID initialization
     *
     * \param manufactureId Manufacture ID to be set up
     * \return Reference to the #VSQAppConfig instance
     */
    VSQAppConfig &
    operator<<(const VSQManufactureId &manufactureId) {
        m_manufactureId = manufactureId;
        return *this;
    }

    /** Sniffer configuration
     *
     * Requires #SNAP_SNIFFER feature to be set up.
     *
     * \param snifferConfig Sniffer configuration
     * \return Reference to the #VSQAppConfig instance
     */
    VSQAppConfig &
    operator<<(const VSQSnapSnifferQmlConfig &snifferConfig) {
        m_snifferConfig = snifferConfig;
        return *this;
    }

    /** Device type initialization
     *
     * \param deviceType Device type to be set up
     * \return Reference to the #VSQAppConfig instance
     */
    VSQAppConfig &
    operator<<(const VSQDeviceType &deviceType) {
        m_deviceType = deviceType;
        return *this;
    }

    /** Device serial number initialization
     *
     * \param VSQDeviceSerial Device serial number to be set up
     * \return Reference to the #VSQAppConfig instance
     */
    VSQAppConfig &
    operator<<(const VSQDeviceSerial &deviceSerial) {
        m_deviceSerial = deviceSerial;
        return *this;
    }

    /** Device roles initialization
     *
     * \param VSQDeviceRoles Device roles to be set up
     * \return Reference to the #VSQAppConfig instance
     */
    VSQAppConfig &
    operator<<(const VSQDeviceRoles &deviceRole) {
        m_deviceRoles = deviceRole;
        return *this;
    }

    /** Logging level initialization
     *
     * \param log_level Logging level to be set up
     * \return Reference to the #VSQAppConfig instance
     */
    VSQAppConfig &
    operator<<(VirgilIoTKit::vs_log_level_t log_level) {
        m_logLevel = log_level;
        return *this;
    }

    /** Get manufacture ID
     *
     * Returns manufacture ID that has been initialized before
     *
     * \return Manufacture ID
     */
    const VSQManufactureId &
    manufactureId() const {
        return m_manufactureId;
    }

    /** Get sniffer configuration
     *
     * Returns sniffer configuration
     *
     * \return Sniffer configuration
     */
    const VSQSnapSnifferQmlConfig &
    snifferConfig() const {
        return m_snifferConfig;
    }

    /** Get device type
     *
     * Returns device type that has been initialized before
     *
     * \return Device type
     */
    const VSQDeviceType &
    deviceType() const {
        return m_deviceType;
    }

    /** Get device serial number
     *
     * Returns device serial number that has been initialized before
     *
     * \return Device serial number
     */
    const VSQDeviceSerial &
    deviceSerial() const {
        return m_deviceSerial;
    }

    /** Get device roles
     *
     * Returns device roles that have been initialized before
     *
     * \return Device roles
     */
    const VSQDeviceRoles &
    deviceRoles() const {
        return m_deviceRoles;
    }

    /** Get logging level
     *
     * Returns logging level that has been initialized before
     *
     * \return Logging level
     */
    VirgilIoTKit::vs_log_level_t
    logLevel() const {
        return m_logLevel;
    }

private:
    VSQManufactureId m_manufactureId;
    VSQDeviceType m_deviceType;
    VSQDeviceSerial m_deviceSerial;
    VSQDeviceRoles m_deviceRoles;
    VSQSnapSnifferQmlConfig m_snifferConfig;
    VirgilIoTKit::vs_log_level_t m_logLevel;
};

#endif // VIRGIL_IOTKIT_QT_APP_CONFIG_H
