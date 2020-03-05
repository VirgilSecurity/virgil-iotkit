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

#if PRVS_CLIENT

#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <private/snap-private.h>
#include <virgil/iot/protocols/snap/prvs/prvs-client.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/logger/logger.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <stdbool.h>
#include <string.h>

#include <virgil/iot/secmodule/secmodule.h>

#define VS_PRVS_RETRY_LIMIT (5)

static vs_snap_service_t _prvs_client = {0, 0, 0, 0, 0};
static vs_snap_prvs_dnid_list_t *_prvs_dnid_list = 0;

// External functions for access to upper level implementations
static vs_snap_prvs_client_impl_t _prvs_impl = {0, 0};

// Last result
#define PRVS_BUF_SZ (1024)
static vs_status_e _last_res = VS_CODE_ERR_PRVS_UNKNOWN;
static uint16_t _last_data_sz = 0;
static uint8_t _last_data[PRVS_BUF_SZ];
static uint32_t _request_id;
/******************************************************************************/
static vs_status_e
_prvs_dnid_process_response(const struct vs_netif_t *netif, const uint8_t *response, const uint16_t response_sz) {
    vs_snap_prvs_dnid_element_t *dnid_response = (vs_snap_prvs_dnid_element_t *)response;

    if (_prvs_dnid_list && _prvs_dnid_list->count < DNID_LIST_SZ_MAX) {

        // Add discovered device
        VS_IOT_MEMCPY(
                &_prvs_dnid_list->elements[_prvs_dnid_list->count], dnid_response, sizeof(vs_snap_prvs_dnid_element_t));
        _prvs_dnid_list->count++;

        return VS_CODE_OK;
    }

    return VS_CODE_ERR_PRVS_UNKNOWN;
}

/******************************************************************************/
static vs_status_e
_prvs_service_response_processor(const struct vs_netif_t *netif,
                                 vs_snap_element_t element_id,
                                 bool is_ack,
                                 const uint8_t *response,
                                 const uint16_t response_sz) {

    VS_IOT_ASSERT(_prvs_impl.stop_wait_func);

    switch (element_id) {
    case VS_PRVS_DNID:
        return _prvs_dnid_process_response(netif, response, response_sz);

    default: {
        if (response_sz && response_sz < PRVS_BUF_SZ) {
            _last_data_sz = response_sz;
            VS_IOT_MEMCPY(_last_data, response, response_sz);
        }

        _prvs_impl.stop_wait_func(&_last_res, is_ack ? VS_CODE_OK : VS_CODE_ERR_PRVS_UNKNOWN);

        return VS_CODE_OK;
    }
    }
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_prvs_client(vs_snap_prvs_client_impl_t impl) {
    _prvs_client.user_data = 0;
    _prvs_client.id = VS_PRVS_SERVICE_ID;
    _prvs_client.request_process = NULL;
    _prvs_client.response_process = _prvs_service_response_processor;
    _prvs_client.periodical_process = NULL;

    _prvs_impl.wait_func = impl.wait_func;
    _prvs_impl.stop_wait_func = impl.stop_wait_func;
    _request_id = 0;
    return &_prvs_client;
}

/******************************************************************************/
vs_status_e
vs_snap_prvs_enum_devices(const vs_netif_t *netif, vs_snap_prvs_dnid_list_t *list, uint32_t wait_ms) {
    vs_status_e ret_code;

    // Set storage for DNID request
    _prvs_dnid_list = list;
    VS_IOT_MEMSET(_prvs_dnid_list, 0, sizeof(*_prvs_dnid_list));

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(netif, NULL, VS_PRVS_SERVICE_ID, VS_PRVS_DNID, 0, 0), "Send request error");

    // Wait request
    vs_impl_msleep(wait_ms);

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_prvs_device_info(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_snap_prvs_devi_t *device_info,
                         uint16_t buf_sz,
                         uint32_t wait_ms) {
    uint16_t sz;

    if (VS_CODE_OK == vs_snap_prvs_get(netif, mac, VS_PRVS_DEVI, (uint8_t *)device_info, buf_sz, &sz, wait_ms)) {
        vs_snap_prvs_devi_t_decode(device_info);
        return VS_CODE_OK;
    }
    return VS_CODE_ERR_PRVS_UNKNOWN;
}

/******************************************************************************/
static void
_reset_last_result() {
    _last_res = VS_CODE_ERR_PRVS_UNKNOWN;
    _last_data_sz = 0;
}

/******************************************************************************/
vs_status_e
vs_snap_prvs_set(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_snap_prvs_element_e element,
                 const uint8_t *data,
                 uint16_t data_sz,
                 uint32_t wait_ms) {

    uint16_t i;
    vs_status_e ret_code;
    uint8_t buf[sizeof(vs_snap_prvs_set_data_t) + data_sz];
    vs_snap_prvs_set_data_t *request = (vs_snap_prvs_set_data_t *)buf;

    VS_IOT_ASSERT(_prvs_impl.wait_func);

    _request_id++;
    request->request_id = _request_id;

    VS_IOT_MEMCPY(request->data, data, data_sz);

    vs_snap_prvs_set_data_t_encode(request);

    _reset_last_result();

    for (i = 0; i < VS_PRVS_RETRY_LIMIT; i++) {

        // Send request
        STATUS_CHECK_RET(vs_snap_send_request(netif, mac, VS_PRVS_SERVICE_ID, element, buf, sizeof(buf)),
                         "Send request error");

        // Wait request
        _prvs_impl.wait_func(wait_ms, &_last_res, VS_CODE_ERR_PRVS_UNKNOWN);

        if (VS_CODE_OK == _last_res) {
            break;
        }
        VS_LOG_DEBUG("vs_snap_prvs_set retry, %d", i + 1);
    }

    return _last_res;
}

/******************************************************************************/
vs_status_e
vs_snap_prvs_get(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_snap_prvs_element_e element,
                 uint8_t *data,
                 uint16_t buf_sz,
                 uint16_t *data_sz,
                 uint32_t wait_ms) {

    uint16_t i;
    vs_status_e ret_code;
    VS_IOT_ASSERT(_prvs_impl.wait_func);

    _reset_last_result();

    for (i = 0; i < VS_PRVS_RETRY_LIMIT; i++) {
        // Send request
        STATUS_CHECK_RET(vs_snap_send_request(netif, mac, VS_PRVS_SERVICE_ID, element, 0, 0), "Send request error");

        // Wait request
        _prvs_impl.wait_func(wait_ms, &_last_res, VS_CODE_ERR_PRVS_UNKNOWN);

        // Pass data
        if (VS_CODE_OK == _last_res && _last_data_sz <= buf_sz) {
            VS_IOT_MEMCPY(data, _last_data, _last_data_sz);
            *data_sz = _last_data_sz;
            return VS_CODE_OK;
        }
        VS_LOG_DEBUG("vs_snap_prvs_get retry, %d", i + 1);
    }

    return VS_CODE_ERR_PRVS_UNKNOWN;
}

/******************************************************************************/
vs_status_e
vs_snap_prvs_save_provision(const vs_netif_t *netif,
                            const vs_mac_addr_t *mac,
                            uint8_t *asav_res,
                            uint16_t buf_sz,
                            uint32_t wait_ms) {
    VS_IOT_ASSERT(asav_res);

    uint16_t sz;
    return vs_snap_prvs_get(netif, mac, VS_PRVS_ASAV, (uint8_t *)asav_res, buf_sz, &sz, wait_ms);
}

/******************************************************************************/
vs_status_e
vs_snap_prvs_sign_data(const vs_netif_t *netif,
                       const vs_mac_addr_t *mac,
                       const uint8_t *data,
                       uint16_t data_sz,
                       uint8_t *signature,
                       uint16_t buf_sz,
                       uint16_t *signature_sz,
                       uint32_t wait_ms) {

    uint16_t i;
    vs_status_e ret_code;
    VS_IOT_ASSERT(_prvs_impl.wait_func);

    _reset_last_result();

    for (i = 0; i < VS_PRVS_RETRY_LIMIT; i++) {
        // Send request
        STATUS_CHECK_RET(vs_snap_send_request(netif, mac, VS_PRVS_SERVICE_ID, VS_PRVS_ASGN, data, data_sz),
                         "Send request error");

        // Wait request
        _prvs_impl.wait_func(wait_ms, &_last_res, VS_CODE_ERR_PRVS_UNKNOWN);

        // Pass data
        if (VS_CODE_OK == _last_res && _last_data_sz <= buf_sz) {
            VS_IOT_MEMCPY(signature, _last_data, _last_data_sz);
            *signature_sz = _last_data_sz;
            return VS_CODE_OK;
        }
        VS_LOG_DEBUG("vs_snap_prvs_sign_data retry, %d", i + 1);
    }

    return VS_CODE_ERR_PRVS_UNKNOWN;
}

/******************************************************************************/
vs_status_e
vs_snap_prvs_set_tl_header(const vs_netif_t *netif,
                           const vs_mac_addr_t *mac,
                           const uint8_t *data,
                           uint16_t data_sz,
                           uint32_t wait_ms) {
    return vs_snap_prvs_set(netif, mac, VS_PRVS_TLH, data, data_sz, wait_ms);
}

/******************************************************************************/
vs_status_e
vs_snap_prvs_set_tl_footer(const vs_netif_t *netif,
                           const vs_mac_addr_t *mac,
                           const uint8_t *data,
                           uint16_t data_sz,
                           uint32_t wait_ms) {
    return vs_snap_prvs_set(netif, mac, VS_PRVS_TLF, data, data_sz, wait_ms);
}

/******************************************************************************/

#endif // PRVS_CLIENT