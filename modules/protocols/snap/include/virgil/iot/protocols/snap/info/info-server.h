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

/*! \file info-server.h
 * \brief INFO for server
 *
 * INFO service is used to provide information about current device state in the local network. Network
 * in this case is limited by SNAP transport protocol.
 *
 * In INFO meaning "Server" is any functional device. "Client" is the special device for statistic collection only.
 * It can be any server PC or MCU device. Servers send their statistic information by startup. Also client can request
 * periodical state sending by polling request.
 *
 * \section info_server_usage INFO Server usage
 *
 * Before first INFO calls usage it is necessary to register INFO Server service :
 *
 * \code
 *
 *    const vs_snap_service_t *snap_info_server;  // INFO Server SNAP service
 *
 *    // Register INFO Server service
 *    snap_info_server = vs_snap_info_server(NULL);
 *    STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO Server service");
 *
 * \endcode
 *
 * \a tl_storage_impl and \a fw_storage_impl are storage implementations. See \ref storage_hal for details.
 *
 */

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_INFO_SERVER_H
#define VS_SECURITY_SDK_SNAP_SERVICES_INFO_SERVER_H

#if INFO_SERVER

#include <virgil/iot/protocols/snap/snap-structs.h>
#include "info-structs.h"

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Startup notification
 *
 * Sends startup notification with device information.
 *
 * \param[in] device #vs_snap_info_device_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_start_notif_srv_cb_t)(vs_snap_info_device_t *device);

/** INFO Server SNAP Service implementation
 *
 * This call returns INFO server implementation. It must be called before any INFO call.
 *
 * \note \a startup_cb can be NULL. In this case standard notifications will be done.
 *
 * \param[in] startup_cb Startup notification server callback. If NULL, it won't be used.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
const vs_snap_service_t *
vs_snap_info_server(vs_snap_info_start_notif_srv_cb_t startup_cb);

/** INFO Server startup notification
 *
 * Sends startup notification.
 *
 * \param[in] netif SNAP service descriptor. If NULL, default one will be used.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_info_start_notification(const vs_netif_t *netif);

/** Set version of firmware to be sent
 *
 * \param[in] ver Firmware version.
 */
void
vs_snap_info_set_firmware_ver(vs_file_version_t ver);

/** Set version of TrustList to be sent
 *
 * \param[in] ver TrustList version.
 */
void
vs_snap_info_set_tl_ver(vs_file_version_t ver);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // INFO_SERVER

#endif // VS_SECURITY_SDK_SNAP_SERVICES_INFO_SERVER_H
