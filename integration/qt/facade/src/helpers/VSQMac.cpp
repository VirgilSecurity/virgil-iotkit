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

const VSQMac broadcastMac(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

const VSQMac invalidMac(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

VSQMac &
VSQMac::set(const QString &mac) {
    static const QChar divider(':');

    if (!mac.isEmpty() && mac.contains(divider)) {
        QStringList macBytes = mac.split(divider);
        if (macBytes.size() == m_mac.size()) {

            for (int pos = 0; pos < m_mac.size(); ++pos) {
                m_mac.data()[pos] = macBytes[pos].toShort(nullptr, 16);
            }

            return *this;
        }
    }

    VS_LOG_WARNING("Incorrect MAC address string : %s", VSQCString(mac));

    // TODO : process empty MAC address
    set(invalidMac);

    return *this;
}

VSQMac &
VSQMac::set(const VirgilIoTKit::vs_mac_addr_t &mac) {
    std::copy(mac.bytes, mac.bytes + sizeof(mac.bytes), m_mac.begin());
    return *this;
}

VSQMac &
VSQMac::set(const uint8_t *bytes) {
    Q_ASSERT(bytes);
    std::copy(bytes, bytes + m_mac.size(), m_mac.begin());
    return *this;
}

VSQMac &
VSQMac::set(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5) {
    m_mac[0] = b0;
    m_mac[1] = b1;
    m_mac[2] = b2;
    m_mac[3] = b3;
    m_mac[4] = b4;
    m_mac[5] = b5;
    return *this;
}

VSQMac &
VSQMac::set(const VSQMac &mac) {
    m_mac = mac.m_mac;
    return *this;
}

VSQMac::operator VirgilIoTKit::vs_mac_addr_t() const {
    VirgilIoTKit::vs_mac_addr_t mac;
    std::copy(m_mac.begin(), m_mac.end(), mac.bytes);
    return mac;
}

QString
VSQMac::description() const {
    QString str;

    str.reserve(m_mac.size() * 3 + 1);

    bool firstSymbol = true;
    for (auto symbol : m_mac) {
        if (firstSymbol) {
            firstSymbol = false;
        } else {
            str += QString(':');
        }

        constexpr QChar fillZero{'0'};
        str += QString("%1").arg((quint8)symbol, 2, 16, fillZero);
    }

    return str;
}
