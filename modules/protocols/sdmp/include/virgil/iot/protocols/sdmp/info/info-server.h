//  Copyright (C) 2015-2019 Virgil Security, Inc.
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
 */
// TODO : examples!

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_INFO_SERVER_H
#define VS_SECURITY_SDK_SDMP_SERVICES_INFO_SERVER_H

#if INFO_SERVER

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/sdmp-structs.h>
#include <virgil/iot/firmware/firmware.h>
#include "info-structs.h"

// TODO : description???
/** Start notification
 *
 * Sends notification with device information.
 *
 * \param[in] device #vs_sdmp_info_device_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_sdmp_info_start_notif_srv_cb_t)(vs_sdmp_info_device_t *device);

/** INFO server callbacks */
typedef struct {
    vs_sdmp_info_start_notif_srv_cb_t device_start_cb; /**< Startup notification */
} vs_sdmp_info_srv_callbacks_t;

/** INFO Server SDMP Service implementation
 *
 * This call returns INFO server implementation. It must be called before any INFO call.
 *
 * \param[in] tl_ctx Trust List storage context. Must not be NULL.
 * \param[in] fw_ctx Firmware storage context. Must not be NULL.
 * \param[in] cb Server callbacks. Must not be NULL.
 * \param[in] self_mac Self MAC address. Must neither be NULL nor broadcast.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
const vs_sdmp_service_t *
vs_sdmp_info_server(vs_storage_op_ctx_t *tl_ctx,
                    vs_storage_op_ctx_t *fw_ctx,
                    const vs_sdmp_info_srv_callbacks_t *cb,
                    const vs_mac_addr_t self_mac);

/** INFO Server startup notification
 *
 * Sends startup notification.
 *
 * \param[in] netif SDMP service descriptor. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_info_start_notification(const vs_netif_t *netif);

#ifdef __cplusplus
}
#endif

#endif // INFO_SERVER

#endif // VS_SECURITY_SDK_SDMP_SERVICES_INFO_SERVER_H
