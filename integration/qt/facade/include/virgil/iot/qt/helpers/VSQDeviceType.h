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

#ifndef VIRGIL_IOTKIT_QT_DEVICE_TYPE_H
#define VIRGIL_IOTKIT_QT_DEVICE_TYPE_H

#include <QtCore>
#include <virgil/iot/provision/provision-structs.h>

class VSQDeviceType {
public:
    VSQDeviceType() : m_deviceType(VS_DEVICE_TYPE_SIZE, 0) {
    }

    VSQDeviceType(const VSQDeviceType &deviceType) : VSQDeviceType() {
        set(deviceType);
    }

    VSQDeviceType(const VirgilIoTKit::vs_device_type_t &buf) {
        set(buf);
    }

    VSQDeviceType &
    operator=(const VSQDeviceType &deviceType) {
        return set(deviceType);
    }

    VSQDeviceType &
    operator=(const VirgilIoTKit::vs_device_type_t &buf) {
        return set(buf);
    }

    bool
    operator==(const VSQDeviceType &deviceType) const {
        return equal(deviceType);
    }

    bool
    operator!=(const VSQDeviceType &deviceType) const {
        return !equal(deviceType);
    }

    QString
    description(bool stopOnZero = true, char nonPrintableSymbols = ' ') const;

    bool
    equal(const VSQDeviceType &deviceType) const {
        return m_deviceType == deviceType.m_deviceType;
    }

    operator const char *() const;
    operator const uint8_t *() const;
    operator QString() const {
        return description();
    }

private:
    QByteArray m_deviceType;

    VSQDeviceType &
    set(const VSQDeviceType &deviceType);

    VSQDeviceType &
    set(const VirgilIoTKit::vs_device_type_t &buf);
};

#endif // VIRGIL_IOTKIT_QT_DEVICE_TYPE_H
