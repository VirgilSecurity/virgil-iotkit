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

/*! \file VSQFeatures.h
 * \brief Virgil IoT Kit Qt framework enabled features
 *
 * #VSQFeatures is used to enumerate features to be enabled.
 *
 * Configure #VSQFeatures by using operator << :
 *
 * \code

    auto features = VSQFeatures() << VSQFeatures::SNAP_INFO_CLIENT << VSQFeatures::SNAP_SNIFFER;

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
        return -1;
    }

 * \endcode
 *
 * Use #VSQFeatures::EFeature enumeration as the list of available features.
 *
 */

#ifndef VIRGIL_IOTKIT_QT_FEATURES_H
#define VIRGIL_IOTKIT_QT_FEATURES_H

#include <QSet>

/** Virgil IoT Kit framework enabled features
 *
 * Initialize this class and use it for #VSQIoTKitFacade::init call.
 */

class VSQFeatures {
public:
    /** Features enumeration */
    enum EFeature { SNAP_CFG_CLIENT,  /**< CFG client service */
                    SNAP_INFO_CLIENT, /**< INFO client service */
        SNAP_SNIFFER      /**< Snap sniffer */
    };

    /** Features set */
    using TSet = QSet<EFeature>;

    /** Add feature
     *
     * Use this function to add \a feature to the list
     *
     * \param feature Feature to enable
     * \return Reference to the #VSQFeatures instance
     */
    VSQFeatures &
    operator<<(EFeature feature) {
        m_features.insert(feature);
        return *this;
    }

    /** Get features set
     *
     * \return Features set
     */
    const TSet &
    featuresSet() const {
        return m_features;
    }

    /** Test feature
     *
     * This function checks that \a feature is present in the features set
     * \param feature Feature to check
     * \return true if \a feature is present in the set
     */
    bool
    hasFeature(EFeature feature) const {
        return m_features.contains(feature);
    }

    /** Test snap feature
     *
     * \return true if snap feature is present in the set
     */
    bool
    hasSnap() const {
        return hasFeature(SNAP_INFO_CLIENT);
    }

private:
    TSet m_features;
};

#endif // VIRGIL_IOTKIT_QT_FEATURES_H
