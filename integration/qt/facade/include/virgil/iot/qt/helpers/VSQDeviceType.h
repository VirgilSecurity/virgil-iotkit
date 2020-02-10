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

/*! \file VSQDeviceType.h
 * \brief Virgil IoT Kit Qt device type
 *
 * #VSQDeviceType is the device type.
 *
 * Configure #VSQDeviceType by using operator = or directly in the constructor :
 * \code

    VirgilIoTKit::vs_device_type_t deviceType;  // Device type buffer
    VSQDeviceType type(deviceType);

 * \endcode
 *
 * You can output device type to the string representation :
 *
 * \code

    VSQDeviceType deviceType;   // Initialized device type
    QString deviceTypeDescription = deviceType;

 * \endcode
 *
 * However, there are different options for text conversion. See #VSQDeviceType::description function
 * for details
 */

#ifndef VIRGIL_IOTKIT_QT_DEVICE_TYPE_H
#define VIRGIL_IOTKIT_QT_DEVICE_TYPE_H

#include <QtCore>
#include <virgil/iot/provision/provision-structs.h>

/** Device type */
class VSQDeviceType {
public:
    /** Default device type constructor */
    VSQDeviceType() : m_deviceType(VS_DEVICE_TYPE_SIZE, 0) {
    }

    /** Copy device type constructor */
    VSQDeviceType(const VSQDeviceType &deviceType) : VSQDeviceType() {
        set(deviceType);
    }

    /** #vs_device_type_t device type constructor */
    VSQDeviceType(const VirgilIoTKit::vs_device_type_t &buf) {
        set(buf);
    }

    /** Assign device type
     *
     * This function calls #set function
     *
     * \param deviceType Device type
     * \return Reference to the #VSQDeviceSerial instance
     */
    VSQDeviceType &
    operator=(const VSQDeviceType &deviceType) {
        return set(deviceType);
    }

    /** Assign device type
     *
     * This function calls #set function
     *
     * \param deviceType Device type
     * \return Reference to the #VSQDeviceSerial instance
     */
    VSQDeviceType &
    operator=(const VirgilIoTKit::vs_device_type_t &buf) {
        return set(buf);
    }

    /** Compare device types
     *
     * This function calls #equal function
     *
     * \param deviceType Device type to compare with the current one
     * \return true if they are equal
     */
    bool
    operator==(const VSQDeviceType &deviceType) const {
        return equal(deviceType);
    }

    /** Describe device type
     *
     * Call this function to receive text description. You can configure it by specifying \a stopOnZero and
     * \a nonPrintableSymbols arguments.
     *
     * \param stopOnZero Stop conversion on the first '\0' symbol. By default it is true.
     * \param nonPrintableSymbols Symbol to output on the non printable symbol. By default it is space.
     *
     * \return Device type text description
     */
    QString
    description(bool stopOnZero = true, char nonPrintableSymbols = ' ') const;

    /** Compare device types
     *
     * \param deviceType Device type to compare with the current one
     * \return true if they are equal
     */
    bool
    equal(const VSQDeviceType &deviceType) const {
        return m_deviceType == deviceType.m_deviceType;
    }

    /** Get device type as symbols array */
    operator const char *() const;

    /** Get device type as bytes array */
    operator const uint8_t *() const;

    /** Get device type text description */
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
