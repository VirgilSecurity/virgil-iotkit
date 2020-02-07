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

/*! \file VSQFileVersion.h
 * \brief Virgil IoT Kit file version
 *
 * #VSQFileVersion is the file version descriptor.
 *
 * Configure #VSQFileVersion in the constructor :
 * \code

    VirgilIoTKit::vs_file_version_t rawFileVersion;  // File version
    VSQFileVersion fileVersion(rawFileVersion);

 * \endcode
 *
 * You can output file version to the string representation :
 *
 * \code

    VSQFileVersion fileVersion;   // Initialized file version
    QString fileVersionDescription = fileVersion;

 * \endcode
 *
 */

#ifndef VIRGIL_IOTKIT_QT_FILE_VERSION_H
#define VIRGIL_IOTKIT_QT_FILE_VERSION_H

#include <QtCore>
#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/info/info-structs.h>

/** Virgil IoT Kit file version */
class VSQFileVersion {
public:
    /** File version default constructor */
    VSQFileVersion();

    /** Initialize file version by using vs_file_version_unpacked_t file version */
    VSQFileVersion(const VirgilIoTKit::vs_file_version_unpacked_t &fileVersion) {
        set(fileVersion);
    }

    /** Initialize file version by using vs_file_version_t file version */
    VSQFileVersion(const VirgilIoTKit::vs_file_version_t &fileVersion) {
        set(fileVersion);
    }

    /** Describe file version
     *
     * \param outputDate Output file date. By default it is false
     * \return File date as string
     */
    QString
    description(bool outputDate = false) const;

    /** Describe file version
     *
     * Create file description by calling #description with default parameters
     *
     * \return File date as string
     */
    operator QString() const {
        return description();
    }

    /** Set file version by using vs_file_version_unpacked_t file version
     *
     * \param fileVersion File version to be copied
     * \return Reference to the #VSQFileVersion instance
     */
    VSQFileVersion &
    operator=(const VirgilIoTKit::vs_file_version_unpacked_t &fileVersion) {
        return set(fileVersion);
    }

    /** Set file version by using vs_file_version_t file version
     *
     * \param fileVersion File version to be copied
     * \return Reference to the #VSQFileVersion instance
     */
    VSQFileVersion &
    operator=(const VirgilIoTKit::vs_file_version_t &fileVersion) {
        return set(fileVersion);
    }

    /** Compare file versions
     *
     * \param fileVersion File version to be compared with the current one
     * \return true if file versions are equal
     */
    bool
    equal(const VSQFileVersion &fileVersion) const;

    /** Compare file versions
     *
     * \param fileVersion File version to be compared with the current one
     * \return true if file versions are equal
     */
    bool
    operator==(const VSQFileVersion &fileVersion) const {
        return equal(fileVersion);
    }

private:
    quint8 m_major;
    quint8 m_minor;
    quint8 m_patch;
    quint32 m_build;
    QDateTime m_timestamp;

    VSQFileVersion &
    set(const VirgilIoTKit::vs_file_version_unpacked_t &fileVersion);

    VSQFileVersion &
    set(const VirgilIoTKit::vs_file_version_t &fileVersion);
};


#endif // VIRGIL_IOTKIT_QT_FILE_VERSION_H
