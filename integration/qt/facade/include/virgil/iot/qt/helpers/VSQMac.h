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

/*! \file VSQMac.h
 * \brief Virgil IoT Kit device MAC address
 *
 * #VSQMac is the device MAC address.
 *
 * Configure #VSQDeviceSerial by using operator = or directly in the constructor :
 * \code

    VirgilIoTKit::vs_mac_addr_t macRaw;  // Device MAC address
    VSQMac mac(macRaw);

 * \endcode
 *
 * You can output MAC address to the string representation :
 *
 * \code

    VSQMac mac;   // Initialized MAC address
    QString macDescription = mac;

 * \endcode
 *
 * There is #broadcastMac MAC address that can be used for broadcast packets.
 * Also #invalidMac is assigned as invalid address.
 */

#ifndef VIRGIL_IOTKIT_QT_MAC_H
#define VIRGIL_IOTKIT_QT_MAC_H

#include <QtCore>
#include <virgil/iot/protocols/snap/snap-structs.h>

/** Virgil IoT Kit device MAC address */
class VSQMac {
public:
    /** Default MAC address constructor */
    VSQMac() : m_mac(6, 0) {
    }

    /** MAC address copy constructor */
    VSQMac(const VSQMac &) = default;

    /** Initialize MAC address from VirgilIoTKit::vs_mac_addr_t */
    VSQMac(const VirgilIoTKit::vs_mac_addr_t &mac) : VSQMac() {
        set(mac);
    }

    /** Initialize MAC address from QString
     *
     * \warning String must be as "11:22:33:44:55:66". If it does not match this template,
     * #invalidMac will be copied
     */
    VSQMac(const QString &mac) : VSQMac() {
        set(mac);
    }

    /** Initialize MAC address from bytes array */
    VSQMac(const quint8 *bytes) : VSQMac() {
        set(bytes);
    }

    /** Initialize MAC address by bytes */
    VSQMac(quint8 b0, quint8 b1, quint8 b2, quint8 b3, quint8 b4, quint8 b5) {
        set(b0, b1, b2, b3, b4, b5);
    }

    /** Assign MAC address
     *
     * \param mac MAC address to be copied
     * \return Reference to the #VSQMac current instance
     */
    VSQMac &
    operator=(const VirgilIoTKit::vs_mac_addr_t &mac) {
        return set(mac);
    }

    /** Assign MAC address
     *
     * \param mac MAC address to be copied
     * \return Reference to the #VSQMac current instance
     */
    VSQMac &
    operator=(const VSQMac &mac) {
        return set(mac);
    }

    /** Assign MAC address
     *
     * \param mac MAC address as string
     * \return Reference to the #VSQMac current instance
     */
    VSQMac &
    operator=(const QString &mac) {
        return set(mac);
    }

    /** Assign MAC address
     *
     * \param mac MAC address as bytes array
     * \return Reference to the #VSQMac current instance
     */
    VSQMac &
    operator=(const quint8 *bytes) {
        return set(bytes);
    }

    /** Compare MAC addresses
     *
     * \param mac MAC address to be compared with the current one
     * \return true if both MAC address are equal
     */
    bool
    operator==(const VSQMac &mac) const {
        return equal(mac);
    }

    /** Describe MAC address
     *
     * Call this function to receive text description.
     *
     * \return MAC address text description
     */
    QString
    description() const;

    /** Compare MAC addresses
     *
     * \param mac MAC address to compare with the current one
     * \return true if they are equal
     */
    bool
    equal(const VSQMac &mac) const {
        return m_mac == mac.m_mac;
    }

    /** Get current MAC address as #vs_mac_addr_t */
    operator VirgilIoTKit::vs_mac_addr_t() const;

    /** Get current MAC address as bytes array */
    operator const char *() const {
        return m_mac.data();
    }

    /** Get MAC address as string */
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

/** Broadcast MAC address */
extern const VSQMac broadcastMac;

/** Invalid MAC address */
extern const VSQMac invalidMac;

#endif // VIRGIL_IOTKIT_QT_MAC_H
