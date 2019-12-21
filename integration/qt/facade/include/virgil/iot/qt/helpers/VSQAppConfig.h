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

#ifndef _VSQ_APP_CONFIG_H_
#define _VSQ_APP_CONFIG_H_

#include <virgil/iot/qt/helpers/VSQManufactureId.h>
#include <virgil/iot/qt/helpers/VSQDeviceType.h>
#include <virgil/iot/qt/helpers/VSQDeviceSerial.h>
#include <virgil/iot/qt/helpers/VSQDeviceRoles.h>
#include <virgil/iot/logger/logger.h>

class VSQAppConfig {
public:
    VSQAppConfig &
    operator<<(const VSQManufactureId &manufactureId) {
        m_manufactureId = manufactureId;
        return *this;
    }

    VSQAppConfig &
    operator<<(const VSQDeviceType &deviceType) {
        m_deviceType = deviceType;
        return *this;
    }

    VSQAppConfig &
    operator<<(const VSQDeviceSerial &deviceSerial) {
        m_deviceSerial = deviceSerial;
        return *this;
    }

    VSQAppConfig &
    operator<<(const VSQDeviceRoles &deviceRole) {
        m_deviceRoles = deviceRole;
        return *this;
    }

    VSQAppConfig &
    operator<<(VirgilIoTKit::vs_log_level_t log_level) {
        m_logLevel = log_level;
        return *this;
    }

    const VSQManufactureId &
    manufactureId() const {
        return m_manufactureId;
    }
    const VSQDeviceType &
    deviceType() const {
        return m_deviceType;
    }
    const VSQDeviceSerial &
    deviceSerial() const {
        return m_deviceSerial;
    }
    const VSQDeviceRoles &
    deviceRoles() const {
        return m_deviceRoles;
    }
    VirgilIoTKit::vs_log_level_t
    logLevel() const {
        return m_logLevel;
    }

private:
    VSQManufactureId m_manufactureId;
    VSQDeviceType m_deviceType;
    VSQDeviceSerial m_deviceSerial;
    VSQDeviceRoles m_deviceRoles;
    VirgilIoTKit::vs_log_level_t m_logLevel;
};

#endif // _VSQ_APP_CONFIG_H_
