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

/*! \file VSQIoTKitFacade.h
 * \brief Facade pattern for Virgil IoT Kit Qt integration
 *
 * #VSQIoTKitFacade class implements facade pattern for Virgil IoT Kit Qt integration usage. This is singleton class.
 *
 * This class contains all elements needed to initialize Virgil IoT KIT Qt library :
 * - #VSQFeatures contains the list of features that application uses (for example, #VSQFeatures::SNAP_INFO_CLIENT)
 * - #VSQImplementations contains the list of implementations shared pointers to use (for example, #VSQUdpBroadcast)
 * - #VSQAppConfig contains application parameters like manufacture ID, device roles, logger initialization
 *
 * \section VSQIoTKitFacade_usage Facade pattern for Virgil IoT Kit Qt integration usage
 *
 * #VSQIoTKitFacade class usage is obvious. You initialize its components and call #VSQIoTKitFacade::init function :
 * \code

    auto features = VSQFeatures() << VSQFeatures::SNAP_INFO_CLIENT;
    auto impl = VSQImplementations() << QSharedPointer<VSQUdpBroadcast>::create();
    auto roles = VSQDeviceRoles() << VirgilIoTKit::VS_SNAP_DEV_CONTROL;
    auto appConfig = VSQAppConfig() << VSQManufactureId() << VSQDeviceType() << VSQDeviceSerial()
                                    << VirgilIoTKit::VS_LOGLEV_DEBUG << roles;

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
    }

 * \endcode
 *
 * See #VSQFeatures, #VSQImplementations and #VSQAppConfig for initialization details.
 *
 * After this call Virgil IoT Kit can be used.
 */

#ifndef VIRGIL_IOTKIT_QT_FACADE_H
#define VIRGIL_IOTKIT_QT_FACADE_H

#include <QtCore>
#include <QtNetwork>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/provision/provision-structs.h>
#include <virgil/iot/qt/helpers/VSQFeatures.h>
#include <virgil/iot/qt/helpers/VSQImplementations.h>
#include <virgil/iot/qt/helpers/VSQAppConfig.h>
#include <virgil/iot/qt/helpers/VSQSingleton.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapServiceBase.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapINFOClient.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapCFGClient.h>
#include <virgil/iot/qt/protocols/snap/VSQSnapSnifferQml.h>

/** Facade pattern for Virgil IoTKit Qt integration
 *
 * This class inherits QObject and VSQSingleton.
 *
 * Initialize Virgil IoT KIT Qt by calling #VSQIoTKitFacade::init function through its instance :
 * \code
 * VSQIoTKitFacade::instance().init( ... )
 * \endcode
 */
class VSQIoTKitFacade : public QObject, public VSQSingleton<VSQIoTKitFacade> {
    Q_OBJECT

public:
    /** Facade initialization
     *
     * Call this function to initialize Virgil IoT Kit facade.
     *
     * \param features Application features
     * \param impl Implementations to be used
     * \param appConfig Application configuration
     * \return true if initialized successfully, false otherwise
     */
    bool
    init(const VSQFeatures &features, const VSQImplementations &impl, const VSQAppConfig &appConfig);

    /** SNAP Sniffer pointer type
     */
    using VSQSnapSnifferPtr = QSharedPointer<VSQSnapSnifferQml>;

    /** Get installed sniffer
     *
     * \warning Function will return nullptr if sniffer is not initialized
     *
     * \return #VSQSnapSnifferQml object or nullptr if sniffer is not initialized
     */
    VSQSnapSnifferPtr snapSniffer()    { return m_snapSniffer; }
    VSQSnapCfgClient & snapCfgClient()    { return VSQSnapCfgClient::instance(); }

    virtual ~VSQIoTKitFacade();

    /** Get Snap INFO Client implementation
     *
     * \warning Function will return nullptr if Snap INFO Client feature is not enabled
     *
     * \return Pointer to the #VSQSnapInfoClient object or nullptr if Snap INFO Client feature is not enabled
     */
    VSQSnapInfoClient *
    snapInfoClient();

private slots:

    void
    onNetifProcess(struct VirgilIoTKit::vs_netif_t *netif, QByteArray data);

private:
    VSQFeatures m_features;
    VSQImplementations m_impl;
    VSQAppConfig m_appConfig;
    VSQSnapSnifferPtr m_snapSniffer;
    QThread *m_snapProcessorThread;

    void
    initSnap();

    void
    registerService(VSQSnapServiceBase &service);

    static VirgilIoTKit::vs_status_e netifProcessCb(struct VirgilIoTKit::vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);
};

#endif // VIRGIL_IOTKIT_QT_FACADE_H
