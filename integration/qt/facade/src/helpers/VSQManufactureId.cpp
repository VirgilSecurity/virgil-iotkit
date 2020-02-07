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

VSQManufactureId &
VSQManufactureId::set(const VSQManufactureId &manufactureId) {
    m_manufactureId = manufactureId.m_manufactureId;
    return *this;
}

VSQManufactureId &
VSQManufactureId::set(const VirgilIoTKit::vs_device_manufacture_id_t &buf) {
    std::copy(buf, buf + sizeof(VirgilIoTKit::vs_device_manufacture_id_t), m_manufactureId.begin());
    return *this;
}

VSQManufactureId::operator const char *() const {
    return m_manufactureId.data();
}

VSQManufactureId::operator const uint8_t *() const {
    return reinterpret_cast<const uint8_t *>(m_manufactureId.data());
}


QString
VSQManufactureId::description(bool stopOnZero, char nonPrintableSymbols) const {
    QString str;
    static const uint8_t ASCII_PRINTABLE_FIRST = 32;
    static const uint8_t ASCII_PRINTABLE_LAST = 126;

    str.reserve(m_manufactureId.size());

    for (auto symbol : m_manufactureId) {
        if (symbol >= ASCII_PRINTABLE_FIRST && symbol <= ASCII_PRINTABLE_LAST)
            str += symbol;
        else if (symbol > 0 || !stopOnZero)
            str += nonPrintableSymbols;
        else
            break;
    }

    return str;
}
