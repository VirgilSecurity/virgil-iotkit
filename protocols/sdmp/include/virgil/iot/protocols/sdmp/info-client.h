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

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_INFO_CLIENT_H
#define VS_SECURITY_SDK_SDMP_SERVICES_INFO_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/info-structs.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/status_code/status_code.h>

typedef vs_status_e (*vs_sdmp_info_wait_t)(uint32_t wait_ms, int* condition, int idle);
typedef vs_status_e (*vs_sdmp_info_stop_wait_t)(int* condition, int expect);

typedef vs_status_e (*vs_sdmp_info_start_notif_cb_t)(vs_sdmp_info_device_t* device);
typedef vs_status_e (*vs_sdmp_info_general_cb_t)(vs_info_general_t* general_info);
typedef vs_status_e (*vs_sdmp_info_statistics_cb_t)(vs_info_statistics_t* statistics);

typedef struct {
    vs_sdmp_info_start_notif_cb_t device_start_cb;
    vs_sdmp_info_general_cb_t general_info_cb;
    vs_sdmp_info_statistics_cb_t statistics_cb;
} vs_sdmp_info_callbacks_t;

typedef struct {
    vs_sdmp_info_wait_t wait_func;
    vs_sdmp_info_stop_wait_t stop_wait_func;
} vs_sdmp_info_impl_t;

const vs_sdmp_service_t*
vs_sdmp_info_client(vs_sdmp_info_impl_t impl, vs_sdmp_info_callbacks_t callbacks);

vs_status_e
vs_sdmp_info_enum_devices(const vs_netif_t* netif,
    vs_sdmp_info_device_t* devices,
    size_t devices_max,
    size_t* devices_cnt,
    uint32_t wait_ms);

vs_status_e
vs_sdmp_info_set_polling(const vs_netif_t* netif,
    const vs_mac_addr_t* mac,
    uint32_t elements, // Multiple vs_sdmp_info_element_mask_e
    bool enable,
    uint16_t period_seconds);

#ifdef __cplusplus
}
#endif

#endif // VS_SECURITY_SDK_SDMP_SERVICES_INFO_CLIENT_H
