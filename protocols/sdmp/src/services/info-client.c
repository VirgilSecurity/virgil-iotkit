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

#include <virgil/iot/protocols/sdmp/info-client.h>
#include <virgil/iot/protocols/sdmp/info-private.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <endian-config.h>

// External functions for access to upper level implementations
static vs_sdmp_info_impl_t _info_impl = {0};

static vs_sdmp_info_device_t *_devices_list = 0;
static size_t _devices_list_max = 0;
static size_t _devices_list_cnt = 0;

/******************************************************************************/
int
vs_sdmp_info_enum_devices(const vs_netif_t *netif,
                          vs_sdmp_info_device_t *devices,
                          size_t devices_max,
                          size_t *devices_cnt,
                          uint32_t wait_ms) {

    VS_IOT_ASSERT(_info_impl.wait_func);

    // Set storage for ENUM request
    _devices_list = devices;
    _devices_list_max = devices_max;
    _devices_list_cnt = 0;
    *devices_cnt = 0;

    // Send request
    if (0 != vs_sdmp_send_request(netif, 0, VS_INFO_SERVICE_ID, VS_INFO_ENUM, NULL, 0)) {
        return -1;
    }

    // Wait request
    vs_global_hal_msleep(wait_ms);

    *devices_cnt = _devices_list_cnt;

    return 0;
}

/******************************************************************************/
int
vs_sdmp_info_get_general(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_info_ginf_response_t *response,
                         uint32_t wait_ms) {
    return -1;
}

/******************************************************************************/
int
vs_sdmp_info_get_stat(const vs_netif_t *netif,
                      const vs_mac_addr_t *mac,
                      vs_info_stat_response_t *response,
                      uint32_t wait_ms) {
    return -1;
}

/******************************************************************************/
int
vs_sdmp_info_set_polling(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         uint32_t elements, // Multiple vs_sdmp_info_element_mask_e
                         bool enable,
                         uint16_t period_seconds) {
    return -1;
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_info_client(vs_sdmp_info_impl_t *impl) {
    CHECK_NOT_ZERO_RET(impl, NULL);

    // Save implementation
    VS_IOT_MEMCPY(&_info_impl, impl, sizeof(_info_impl));


    return 0;
}

/******************************************************************************/
// static int
//_info_request_processor(const struct vs_netif_t *netif,
//                        vs_sdmp_element_t element_id,
//                        const uint8_t *request,
//                        const uint16_t request_sz,
//                        uint8_t *response,
//                        const uint16_t response_buf_sz,
//                        uint16_t *response_sz) {
//    (void)netif;
//
//    *response_sz = 0;
//
//    switch (element_id) {
//
//    case VS_INFO_GINF:
//        return vs_info_GINF_request_processing(request, request_sz, response, response_buf_sz, response_sz);
//
//    default:
//        VS_LOG_ERROR("Unsupported INFO command");
//        VS_IOT_ASSERT(false);
//        return VS_SDMP_COMMAND_NOT_SUPPORTED;
//    }
//}

/******************************************************************************/
// const vs_sdmp_service_t *
// vs_sdmp_info_client(vs_storage_op_ctx_t *tl_ctx,
//                    vs_storage_op_ctx_t *fw_ctx,
//                    const vs_fw_manufacture_id_t manufacturer_id,
//                    const vs_fw_device_type_t device_type) {
//
//    static vs_sdmp_service_t _info = {0};
//
//    CHECK_NOT_ZERO_RET(tl_ctx, NULL);
//    CHECK_NOT_ZERO_RET(fw_ctx, NULL);
//
//    _tl_ctx = tl_ctx;
//    _fw_ctx = fw_ctx;
//    VS_IOT_MEMCPY(_manufacture_id, manufacturer_id, sizeof(_manufacture_id));
//    VS_IOT_MEMCPY(_device_type, device_type, sizeof(_device_type));
//
//    _info.user_data = NULL;
//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wmultichar"
//    _info.id = HTONL_IN_COMPILE_TIME('INFO');
//#pragma GCC diagnostic pop
//    _info.request_process = NULL;
//    _info.response_process = NULL;
//    _info.periodical_process = NULL;
//
//    return &_info;
//}
//
///******************************************************************************/