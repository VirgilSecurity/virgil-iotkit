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

/*! \file VSQSnapServiceBase.h
 * \brief SNAP protocol's service interface
 *
 * #VSQSnapServiceBase is used as base class for SNAP protocol services. #VSQSnapInfoClient is INFO Client service based
 * on this interface.
 *
 */

#ifndef _VIRGIL_IOTKIT_QT_SNAP_SERVICE_H_
#define _VIRGIL_IOTKIT_QT_SNAP_SERVICE_H_

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/qt/helpers/VSQFeatures.h>

/** SNAP service base class */
class VSQSnapServiceBase {
public:
    virtual ~VSQSnapServiceBase() = default;

    /** Get service interface
     *
     * \return Service interface
     */
    virtual const VirgilIoTKit::vs_snap_service_t *
    serviceInterface() = 0;

    /** Get service feature
     *
     * \return Service feature
     */
    virtual VSQFeatures::EFeature
    serviceFeature() const = 0;

    /** Get service name
     *
     * \return Service name
     */
    virtual const QString &
    serviceName() const = 0;
};

#endif // _VIRGIL_IOTKIT_QT_SNAP_SERVICE_H_
