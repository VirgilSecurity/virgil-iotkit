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

/*! \file high-level.h
 * \brief High level API
 *
 * API to simplify IoTKit usage
 *
 */

#ifndef VS_HIGH_LEVEL_H
#define VS_HIGH_LEVEL_H

#include <stdarg.h>
#include <string.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib-config.h>

#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/provision/provision-structs.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/storage_hal/storage_hal.h>

#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/msgr/msgr-client.h>
#include <virgil/iot/protocols/snap/msgr/msgr-server.h>
#include <virgil/iot/protocols/snap/cfg/cfg-server.h>

// Types

/** Callback function to inform about requested reboot
 */
typedef void (*vs_reboot_request_cb_t)(void);

// Structures

/** Container of pointers to callback functions for IoTKit Events
 *
 * Fill required callbacks to receive information about different events of IoTKit
 */
typedef struct {
    vs_reboot_request_cb_t reboot_request_cb;
} vs_iotkit_events_t;

// Functions

/** Initialize High Level
 *
 * Initializes IoTKit.
 *
 * \param[in] manufacture Manufacture ID
 * \param[in] device_type Device type
 * \param[in] serial Serial number of device
 * \param[in] device_roles Device roles. Mask formed from vs_snap_device_role_e element.
 * \param[in] secmodule Security module implementation. You can use default implementation
 * \param[in] tl_storage_impl Storage context. Must not be NULL.
 * \param[in] secbox_storage_impl Storage context. Can be NULL.
 * \param[in] netif_impl NULL-terminated array of #vs_netif_t
 * \param[in] iotkit_events #vs_iotkit_events_t Callbacks for different IoTKit events
 *
 * \return #VS_CODE_OK in case of success or error code.
 */

vs_status_e
vs_high_level_init(vs_device_manufacture_id_t manufacture_id,
                   vs_device_type_t device_type,
                   vs_device_serial_t serial,
                   uint32_t device_roles,
                   vs_secmodule_impl_t *secmodule_impl,
                   vs_storage_op_ctx_t *tl_storage_impl,
#if FLDT_SERVER || FLDT_CLIENT
                   vs_storage_op_ctx_t *firmware_storage_impl,
#endif // FLDT_SERVER || FLDT_CLIENT
                   vs_storage_op_ctx_t *secbox_storage_impl,
                   vs_netif_t *netif_impl[],
#if MSGR_SERVER
                   vs_snap_msgr_server_service_t msgr_server_cb,
#endif
#if MSGR_CLIENT
                   vs_snap_msgr_client_service_t msgr_client_cb,
#endif
#if CFG_SERVER
                   vs_snap_cfg_server_service_t cfg_server_cb,
#endif
                   vs_netif_process_cb_t packet_preprocessor_cb,
                   vs_iotkit_events_t iotkit_events);

/** Destroy IoTKit
 *
 * \return #VS_CODE_OK in case of success or error code.
 */

vs_status_e
vs_high_level_deinit(void);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_HIGH_LEVEL_H
