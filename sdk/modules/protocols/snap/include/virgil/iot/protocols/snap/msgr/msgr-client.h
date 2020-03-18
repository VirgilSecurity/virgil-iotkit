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

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_MSGR_CLIENT_H
#define VS_SECURITY_SDK_SNAP_SERVICES_MSGR_CLIENT_H

#if MSGR_CLIENT

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/msgr/msgr-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

typedef vs_status_e (*vs_snap_msgr_start_notif_cb_t)(vs_snap_msgr_device_t *device);

typedef vs_status_e (*vs_snap_msgr_device_data_cb_t)(uint8_t *data, uint32_t data_sz);

typedef struct {
    vs_snap_msgr_start_notif_cb_t device_start; /**< Startup notification */
    vs_snap_msgr_device_data_cb_t device_data;  /**< Process received data from a device */
} vs_snap_msgr_client_service_t;

vs_status_e
vs_snap_msgr_enum_devices(const vs_netif_t *netif,
                          vs_snap_msgr_device_t *devices,
                          size_t devices_max,
                          size_t *devices_cnt,
                          uint32_t wait_ms);

vs_status_e
vs_snap_msgr_set_polling(const vs_netif_t *netif, const vs_mac_addr_t *mac, bool enable, uint16_t period_seconds);

const vs_snap_service_t *
vs_snap_msgr_client(vs_snap_msgr_client_service_t impl);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // MSGR_CLIENT
#endif // VS_SECURITY_SDK_SNAP_SERVICES_MSGR_CLIENT_H
