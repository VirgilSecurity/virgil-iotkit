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

/*! \file VSQImplementations.h
 * \brief Virgil IoT Kit Framework implementations configuration
 *
 * #VSQImplementations is used to initialize necessary configurations.
 *
 * For now it is necessary to specify network interface implementation. You need to implement your own as
 * #VSQNetifBase child or use #VSQUdpBroadcast.
 *
 * Configure #VSQImplementations by using operator << :
 * \code
    auto impl = VSQImplementations() << QSharedPointer<VSQUdpBroadcast>::create();

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
    }
 * \endcode
 *
 */

#ifndef VIRGIL_IOTKIT_QT_IMPLEMENTATIONS_H
#define VIRGIL_IOTKIT_QT_IMPLEMENTATIONS_H

#include <QtCore>

class VSQNetifBase;

/** Implementations configuration
 *
 * Initialize this class and use it for #VSQIoTKitFacade::init call.
 */
class VSQImplementations {
public:

    typedef  QList<QSharedPointer<VSQNetifBase>> VSQNetifList;

    /** Add network interface implementation
     *
     * \param netif Network interface as #VSQNetifBase child implementation. You could use #VSQUdpBroadcast as default one
     * \return Reference to the #VSQImplementations instance
     */
    VSQImplementations &
    operator<<(QSharedPointer<VSQNetifBase> netif) {
        m_netifs.push_back(netif);
        return *this;
    }

    /** Initialised network interface implementation
     *
     * \warning Initialize network interface prior to this function call. In other case you will receive assertion error
     *
     * \return Current network interface implementation
     */
    VSQNetifList &
    netifs() {
        return m_netifs;
    }

private:
    VSQNetifList m_netifs;
};

#endif // VIRGIL_IOTKIT_QT_IMPLEMENTATIONS_H
