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

#ifndef VIRGIL_IOTKIT_QT_MAC_H
#define VIRGIL_IOTKIT_QT_MAC_H

#include <QtCore>
#include <virgil/iot/protocols/snap/snap-structs.h>

class VSQMac {
public:
    VSQMac() : m_mac(6, 0) {
    }

    VSQMac(const VSQMac &) = default;
    VSQMac(const VirgilIoTKit::vs_mac_addr_t &mac) : VSQMac() {
        set(mac);
    }
    VSQMac(const QString &mac) : VSQMac() {
        set(mac);
    }

    VSQMac(const quint8 *bytes) : VSQMac() {
        set(bytes);
    }

    VSQMac(quint8 b0, quint8 b1, quint8 b2, quint8 b3, quint8 b4, quint8 b5) {
        set(b0, b1, b2, b3, b4, b5);
    }

    VSQMac &
    operator=(const VirgilIoTKit::vs_mac_addr_t &mac) {
        return set(mac);
    }

    VSQMac &
    operator=(const VSQMac &mac) {
        return set(mac);
    }

    bool
    operator==(const VSQMac &mac) const {
        return equal(mac);
    }

    bool
    operator!=(const VSQMac &mac) const {
        return !equal(mac);
    }

    QString
    description() const;

    bool
    equal(const VSQMac &mac) const {
        return m_mac == mac.m_mac;
    }

    operator VirgilIoTKit::vs_mac_addr_t() const;
    operator const char *() const {
        return m_mac.data();
    }

    operator QString() const {
        return description();
    }

private:
    QByteArray m_mac;

    VSQMac &
    set(const QString &mac);

    VSQMac &
    set(const VirgilIoTKit::vs_mac_addr_t &mac);

    VSQMac &
    set(const quint8 *bytes);

    VSQMac &
    set(quint8 b0, quint8 b1, quint8 b2, quint8 b3, quint8 b4, quint8 b5);

    VSQMac &
    set(const VSQMac &mac);
};

extern const VSQMac broadcastMac;

#endif // VIRGIL_IOTKIT_QT_MAC_H
