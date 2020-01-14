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

/*! \file VSQDeviceSerial.h
 * \brief Virgil IoT Kit Qt device serial number
 *
 * #VSQDeviceSerial is the device serial number.
 *
 * Configure #VSQDeviceSerial by using operator = or directly in the constructor :
 * \code

    VirgilIoTKit::vs_device_serial_t deviceSerial;  // Device serial number
    VSQDeviceSerial serial(deviceSerial);

 * \endcode
 *
 * You can output device serial number to the string representation :
 *
 * \code

    VSQDeviceSerial serial;   // Initialized device serial number
    QString serialDescription = serial;

 * \endcode
 *
 */

#ifndef VIRGIL_IOTKIT_QT_DEVICE_SERIAL_H
#define VIRGIL_IOTKIT_QT_DEVICE_SERIAL_H

#include <QtCore>
#include <virgil/iot/provision/provision-structs.h>

/** Device serial number */
class VSQDeviceSerial {
public:
    /** Default serial number constructor */
    VSQDeviceSerial() : m_deviceSerial(VS_DEVICE_SERIAL_SIZE, 0) {
    }

    /** Copy serial number constructor */
    VSQDeviceSerial(const VSQDeviceSerial &deviceSerial) : VSQDeviceSerial() {
        set(deviceSerial);
    }

    /** #vs_device_serial_t serial number constructor */
    VSQDeviceSerial(const VirgilIoTKit::vs_device_serial_t &buf) : VSQDeviceSerial() {
        set(buf);
    }

    /** Assign serial number
     *
     * \param deviceSerial Device serial number
     * \return Reference to the #VSQDeviceSerial instance
     */
    VSQDeviceSerial &
    operator=(const VSQDeviceSerial &deviceSerial) {
        return set(deviceSerial);
    }

    /** Assign serial number
     *
     * \param deviceSerial Device serial number
     * \return Reference to the #VSQDeviceSerial instance
     */
    VSQDeviceSerial &
    operator=(const VirgilIoTKit::vs_device_serial_t &buf) {
        return set(buf);
    }

    /** Compare serial numbers
     *
     * This function calls #equal function
     *
     * \param deviceSerial Serial number to compare with the current one
     * \return true if they are equal
     */
    bool
    operator==(const VSQDeviceSerial &deviceSerial) const {
        return equal(deviceSerial);
    }

    /** Describe device serial number
     *
     * Call this function to receive text description.
     *
     * \return Device serial number text description
     */
    QString
    description() const;

    /** Compare serial numbers
     *
     * \param deviceSerial Serial number to compare with the current one
     * \return true if they are equal
     */
    bool
    equal(const VSQDeviceSerial &deviceSerial) const {
        return m_deviceSerial == deviceSerial.m_deviceSerial;
    }

    /** Get serial number as symbols array */
    operator const char *() const;

    /** Get serial number as bytes array */
    operator const uint8_t *() const;

    /** Get serial number text description */
    operator QString() const {
        return description();
    }

private:
    QByteArray m_deviceSerial;

    VSQDeviceSerial &
    set(const VSQDeviceSerial &deviceSerial);

    VSQDeviceSerial &
    set(const VirgilIoTKit::vs_device_serial_t &buf);
};

#endif // VIRGIL_IOTKIT_QT_DEVICE_SERIAL_H
