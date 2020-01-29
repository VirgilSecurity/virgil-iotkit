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

/*! \file VSQManufactureId.h
 * \brief Device's manufacture ID
 *
 * #VSQManufactureId is the manufacture identifier. This identifier is necessary to match files received
 * from Cloud and from Gateway.
 *
 * Configure #VSQManufactureId by using operator = or directly in the constructor :
 * \code

    VirgilIoTKit::vs_device_manufacture_id_t rawManufactureId;  // Manufacture identifier
    VSQManufactureId manufactureId(rawManufactureId);

 * \endcode
 *
 * You can output manufacture identifier to the string representation :
 *
 * \code

    VSQManufactureId manufactureId;   // Initialized manufacture identifier
    QString manufactureIdDescription = manufactureId;

 * \endcode
 *
 */

#ifndef VIRGIL_IOTKIT_QT_MANUFACTURE_ID_H
#define VIRGIL_IOTKIT_QT_MANUFACTURE_ID_H

#include <QtCore>
#include <virgil/iot/protocols/snap.h>

/** Manufacture identifier */
class VSQManufactureId {
public:
    /** Default manufacture identifier constructor */
    VSQManufactureId() : m_manufactureId(VS_DEVICE_MANUFACTURE_ID_SIZE, 0) {
    }

    /** Manufacture identifier copy constructor */
    VSQManufactureId(const VSQManufactureId &manufactureId) : VSQManufactureId() {
        set(manufactureId);
    }

    /** Initialize manufacture identifier from VirgilIoTKit::vs_device_manufacture_id_t */
    VSQManufactureId(const VirgilIoTKit::vs_device_manufacture_id_t &buf) : VSQManufactureId() {
        set(buf);
    }

    /** Assign manufacture identifier
     *
     * \param manufactureId Manufacture identifier to copy
     * \return Current #VSQManufactureId instance
     */
    VSQManufactureId &
    operator=(const VSQManufactureId &manufactureId) {
        return set(manufactureId);
    }

    /** Assign manufacture identifier
     *
     * \param buf Manufacture identifier buffer to copy
     * \return Current #VSQManufactureId instance
     */
    VSQManufactureId &
    operator=(const VirgilIoTKit::vs_device_manufacture_id_t &buf) {
        return set(buf);
    }

    /** Compare manufacture identifiers
     *
     * \param manufactureId Manufacture identifier to be compared with the current one
     * \return true if both manufacture identifiers are equal
     */
    bool
    operator==(const VSQManufactureId &manufactureId) const {
        return equal(manufactureId);
    }

    /** Describe manufacture identifier
     *
     * Call this function to receive text description. You can configure it by specifying \a stopOnZero and
     * \a nonPrintableSymbols arguments.
     *
     * \param stopOnZero Stop conversion on the first '\0' symbol. By default it is true.
     * \param nonPrintableSymbols Symbol to output on the non printable symbol. By default it is space.
     *
     * \return Manufacture identifier text description
     */
    QString
    description(bool stopOnZero = true, char nonPrintableSymbols = ' ') const;

    /** Compare manufacture identifiers
     *
     * \param manufactureId Device type to compare with the current one
     * \return true if they are equal
     */
    bool
    equal(const VSQManufactureId &manufactureId) const {
        return m_manufactureId == manufactureId.m_manufactureId;
    }

    /** Get manufacture identifier as symbols array */
    operator const char *() const;

    /** Get manufacture identifier as bytes array */
    operator const uint8_t *() const;

    /** Get manufacture identifier text description */
    operator QString() const {
        return description();
    }

private:
    QByteArray m_manufactureId;

    VSQManufactureId &
    set(const VSQManufactureId &manufactureId);

    VSQManufactureId &
    set(const VirgilIoTKit::vs_device_manufacture_id_t &buf);
};

#endif // VIRGIL_IOTKIT_QT_MANUFACTURE_ID_H
