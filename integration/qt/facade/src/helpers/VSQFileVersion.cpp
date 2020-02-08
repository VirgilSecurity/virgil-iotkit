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

VSQFileVersion::VSQFileVersion() : m_major(0), m_minor(0), m_patch(0), m_build(0) {
}

VSQFileVersion &
VSQFileVersion::set(const VirgilIoTKit::vs_file_version_t &fileVersion) {
    m_major = fileVersion.major;
    m_minor = fileVersion.minor;
    m_patch = fileVersion.patch;
    m_build = fileVersion.build;
    m_timestamp = QDateTime::fromSecsSinceEpoch(fileVersion.timestamp, Qt::UTC, VS_START_EPOCH);

    return *this;
}

VSQFileVersion &
VSQFileVersion::set(const VirgilIoTKit::vs_file_version_unpacked_t &fileVersion) {
    m_major = fileVersion.major;
    m_minor = fileVersion.minor;
    m_patch = fileVersion.patch;
    m_build = fileVersion.build;
    m_timestamp = QDateTime::fromSecsSinceEpoch(fileVersion.timestamp, Qt::UTC, VS_START_EPOCH);

    return *this;
}

QString
VSQFileVersion::description(bool outputDate) const {
    QString res = QString("%1.%2.%3.%4").arg(m_major).arg(m_minor).arg(m_patch).arg(m_build);

    if (outputDate) {
        res += QString(", %1").arg(m_timestamp.toString("hh:mm:ss"));
    }

    return res;
}

bool
VSQFileVersion::equal(const VSQFileVersion &fileVersion) const {
    return m_major == fileVersion.m_major && m_minor == fileVersion.m_minor && m_patch == fileVersion.m_patch &&
           m_build == fileVersion.m_build && m_timestamp == fileVersion.m_timestamp;
}
