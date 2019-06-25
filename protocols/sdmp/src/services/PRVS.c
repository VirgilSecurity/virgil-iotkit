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

#include <virgil/iot/protocols/sdmp/PRVS.h>
#include <virgil/iot/protocols/sdmp/sdmp_private.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/sdmp/generated/sdmp_cvt.h>
#include "hal/macro.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <global-hal.h>

static vs_sdmp_service_t _prvs_service = {0};
static bool _prvs_service_ready = false;
static vs_sdmp_prvs_dnid_list_t *_prvs_dnid_list = 0;

// External functions for access to upper level implementations
static vs_sdmp_prvs_impl_t _prvs_impl = {0};

#define RES_UNKNOWN (-2)
#define RES_NEGATIVE (-1)
#define RES_OK (0)

// Last result
#define PRVS_BUF_SZ (1024)
static int _last_res = RES_UNKNOWN;
static size_t _last_data_sz = 0;
static uint8_t _last_data[PRVS_BUF_SZ];
/******************************************************************************/
int
vs_sdmp_prvs_configure_hal(vs_sdmp_prvs_impl_t impl) {
    _prvs_impl = impl;
    return 0;
}

/******************************************************************************/
static int
_prvs_dnid_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const size_t request_sz,
                           uint8_t *response,
                           const size_t response_buf_sz,
                           size_t *response_sz) {

    vs_sdmp_prvs_dnid_element_t *dnid_response = (vs_sdmp_prvs_dnid_element_t *)response;

    VS_ASSERT(_prvs_impl.dnid_func);

    if (0 != _prvs_impl.dnid_func()) {
        return -1;
    }

    const size_t required_sz = sizeof(vs_sdmp_prvs_dnid_element_t);
    VS_ASSERT(response_buf_sz >= required_sz);

    vs_sdmp_mac_addr(netif, &dnid_response->mac_addr);
    dnid_response->device_type = 0;
    *response_sz = required_sz;

    return 0;
}

/******************************************************************************/
static int
_prvs_dnid_process_response(const struct vs_netif_t *netif, const uint8_t *response, const size_t response_sz) {

    vs_sdmp_prvs_dnid_element_t *dnid_response = (vs_sdmp_prvs_dnid_element_t *)response;

    if (_prvs_dnid_list && _prvs_dnid_list->count < DNID_LIST_SZ_MAX) {
        memcpy(&_prvs_dnid_list->elements[_prvs_dnid_list->count], dnid_response, sizeof(vs_sdmp_prvs_dnid_element_t));
        _prvs_dnid_list->count++;

        return 0;
    }

    return -1;
}

/******************************************************************************/
static int
_prvs_key_save_process_request(const struct vs_netif_t *netif,
                               vs_sdmp_element_t element_id,
                               const uint8_t *key,
                               const size_t key_sz) {
    VS_ASSERT(_prvs_impl.save_data_func);
    return _prvs_impl.save_data_func(element_id, key, key_sz);
}

/******************************************************************************/
static int
_prvs_devi_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const size_t request_sz,
                           uint8_t *response,
                           const size_t response_buf_sz,
                           size_t *response_sz) {

    vs_sdmp_prvs_devi_t *devi_response = (vs_sdmp_prvs_devi_t *)response;

    VS_ASSERT(_prvs_impl.device_info_func);
    // TODO: FIX SIZE
    if (0 != _prvs_impl.device_info_func(devi_response, 128)) {
        return -1;
    }

    // Normalize byte order
    vs_sdmp_prvs_devi_t_encode(devi_response);

    *response_sz = sizeof(vs_sdmp_prvs_devi_t) + devi_response->signature.val_sz;

    return 0;
}

/******************************************************************************/
static int
_prvs_asav_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const size_t request_sz,
                           uint8_t *response,
                           const size_t response_buf_sz,
                           size_t *response_sz) {

    vs_sdmp_pubkey_t *asav_response = (vs_sdmp_pubkey_t *)response;

    VS_ASSERT(_prvs_impl.finalize_storage_func);
    if (0 != _prvs_impl.finalize_storage_func(asav_response)) {
        return -1;
    }

    *response_sz = sizeof(vs_sdmp_pubkey_t);

    return 0;
}

/******************************************************************************/
static int
_prvs_asgn_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const size_t request_sz,
                           uint8_t *response,
                           const size_t response_buf_sz,
                           size_t *response_sz) {

    VS_ASSERT(_prvs_impl.sign_data_func);
    if (0 != _prvs_impl.sign_data_func(request, request_sz, response, response_buf_sz, response_sz)) {
        return -1;
    }

    return 0;
}

/******************************************************************************/
static int
_prvs_start_tl_process_request(const struct vs_netif_t *netif, const uint8_t *request, const size_t request_sz) {

    VS_ASSERT(_prvs_impl.start_save_tl_func);
    if (0 != _prvs_impl.start_save_tl_func(request, request_sz)) {
        return -1;
    }

    return 0;
}

/******************************************************************************/
static int
_prvs_tl_part_process_request(const struct vs_netif_t *netif, const uint8_t *request, const size_t request_sz) {

    VS_ASSERT(_prvs_impl.save_tl_part_func);
    if (0 != _prvs_impl.save_tl_part_func(request, request_sz)) {
        return -1;
    }

    return 0;
}

/******************************************************************************/
static int
_prvs_finalize_tl_process_request(const struct vs_netif_t *netif, const uint8_t *request, const size_t request_sz) {

    VS_ASSERT(_prvs_impl.finalize_tl_func);
    if (0 != _prvs_impl.finalize_tl_func(request, request_sz)) {
        return -1;
    }

    return 0;
}

/******************************************************************************/
static int
_prvs_service_request_processor(const struct vs_netif_t *netif,
                                vs_sdmp_element_t element_id,
                                const uint8_t *request,
                                const size_t request_sz,
                                uint8_t *response,
                                const size_t response_buf_sz,
                                size_t *response_sz) {

    // Process DNID

    *response_sz = 0;

    switch (element_id) {
    case VS_PRVS_DNID:
        return _prvs_dnid_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    case VS_PRVS_DEVI:
        return _prvs_devi_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    case VS_PRVS_ASAV:
        return _prvs_asav_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    case VS_PRVS_ASGN:
        return _prvs_asgn_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    case VS_PRVS_TLH:
        return _prvs_start_tl_process_request(netif, request, request_sz);

    case VS_PRVS_TLC:
        return _prvs_tl_part_process_request(netif, request, request_sz);

    case VS_PRVS_TLF:
        return _prvs_finalize_tl_process_request(netif, request, request_sz);

    case VS_PRVS_PBR1:
    case VS_PRVS_PBR2:
    case VS_PRVS_PBA1:
    case VS_PRVS_PBA2:
    case VS_PRVS_PBT1:
    case VS_PRVS_PBT2:
    case VS_PRVS_PBF1:
    case VS_PRVS_PBF2:
    case VS_PRVS_SGNP:
        return _prvs_key_save_process_request(netif, element_id, request, request_sz);

    default: {
    }
    }

    return -1;
}

/******************************************************************************/
static int
_prvs_service_response_processor(const struct vs_netif_t *netif,
                                 vs_sdmp_element_t element_id,
                                 bool is_ack,
                                 const uint8_t *response,
                                 const size_t response_sz) {

    VS_ASSERT(_prvs_impl.stop_wait_func);

    switch (element_id) {
    case VS_PRVS_DNID:
        return _prvs_dnid_process_response(netif, response, response_sz);

    default: {
        if (response_sz && response_sz < PRVS_BUF_SZ) {
            _last_data_sz = response_sz;
            memcpy(_last_data, response, response_sz);
        }

        _prvs_impl.stop_wait_func(&_last_res, is_ack ? RES_OK : RES_NEGATIVE);

        return 0;
    }
    }
}

/******************************************************************************/
static void
_prepare_prvs_service() {
    _prvs_service.user_data = 0;
    _prvs_service.id = HTONL_IN_COMPILE_TIME('PRVS');
    _prvs_service.request_process = _prvs_service_request_processor;
    _prvs_service.response_process = _prvs_service_response_processor;
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_prvs_service() {
    if (!_prvs_service_ready) {
        _prepare_prvs_service();
        _prvs_service_ready = true;
    }

    return &_prvs_service;
}

/******************************************************************************/
static int
_send_request(const vs_netif_t *netif,
              const vs_mac_addr_t *mac,
              vs_sdmp_prvs_element_t element,
              const uint8_t *data,
              size_t data_sz) {
    uint8_t buffer[sizeof(vs_sdmp_packet_t) + data_sz];
    vs_sdmp_packet_t *packet;

    memset(buffer, 0, sizeof(buffer));

    // Prepare pointers
    packet = (vs_sdmp_packet_t *)buffer;

    // Prepare request
    packet->header.element_id = element;
    packet->header.service_id = _prvs_service.id;
    packet->header.content_size = data_sz;
    if (data_sz) {
        memcpy(packet->content, data, data_sz);
    }
    _sdmp_fill_header(mac, packet);

    // Normalize byte order
    vs_sdmp_packet_t_encode(packet);

    // Send request
    return vs_sdmp_send(netif, buffer, sizeof(vs_sdmp_packet_t) + packet->header.content_size);
}
/******************************************************************************/
int
vs_sdmp_prvs_uninitialized_devices(const vs_netif_t *netif, vs_sdmp_prvs_dnid_list_t *list, size_t wait_ms) {

    VS_ASSERT(_prvs_impl.wait_func);

    // Set storage for DNID request
    _prvs_dnid_list = list;
    memset(_prvs_dnid_list, 0, sizeof(*_prvs_dnid_list));

    // Send request
    if (0 != _send_request(netif, 0, VS_PRVS_DNID, 0, 0)) {
        return -1;
    }

    // Wait request
    vs_global_hal_msleep(wait_ms);

    return 0;
}

/******************************************************************************/
int
vs_sdmp_prvs_device_info(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_sdmp_prvs_devi_t *device_info,
                         size_t buf_sz,
                         size_t wait_ms) {
    size_t sz;
    if (0 == vs_sdmp_prvs_get(netif, mac, VS_PRVS_DEVI, (uint8_t *)device_info, buf_sz, &sz, wait_ms)) {
        vs_sdmp_prvs_devi_t_decode(device_info);
        return 0;
    }
    return -1;
}

/******************************************************************************/
static void
_reset_last_result() {
    _last_res = RES_UNKNOWN;
    _last_data_sz = 0;
}

/******************************************************************************/
int
vs_sdmp_prvs_set(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_sdmp_prvs_element_t element,
                 const uint8_t *data,
                 size_t data_sz,
                 size_t wait_ms) {

    VS_ASSERT(_prvs_impl.wait_func);

    _reset_last_result();

    // Send request
    if (0 != _send_request(netif, mac, element, data, data_sz)) {
        return -1;
    }

    // Wait request
    _prvs_impl.wait_func(wait_ms, &_last_res, RES_UNKNOWN);

    return _last_res;
}

/******************************************************************************/
int
vs_sdmp_prvs_get(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_sdmp_prvs_element_t element,
                 uint8_t *data,
                 size_t buf_sz,
                 size_t *data_sz,
                 size_t wait_ms) {

    VS_ASSERT(_prvs_impl.wait_func);

    _reset_last_result();

    // Send request
    if (0 != _send_request(netif, mac, element, 0, 0)) {
        return -1;
    }

    // Wait request
    _prvs_impl.wait_func(wait_ms, &_last_res, RES_UNKNOWN);

    // Pass data
    if (0 == _last_res && _last_data_sz <= buf_sz) {
        memcpy(data, _last_data, _last_data_sz);
        *data_sz = _last_data_sz;
        return 0;
    }

    return -1;
}

/******************************************************************************/
int
vs_sdmp_prvs_save_provision(const vs_netif_t *netif,
                            const vs_mac_addr_t *mac,
                            vs_sdmp_pubkey_t *asav_res,
                            size_t wait_ms) {
    VS_ASSERT(asav_res);

    size_t sz;
    return vs_sdmp_prvs_get(netif, mac, VS_PRVS_ASAV, (uint8_t *)asav_res, sizeof(vs_sdmp_pubkey_t), &sz, wait_ms);
}

/******************************************************************************/
int
vs_sdmp_prvs_sign_data(const vs_netif_t *netif,
                       const vs_mac_addr_t *mac,
                       const uint8_t *data,
                       size_t data_sz,
                       uint8_t *signature,
                       size_t buf_sz,
                       size_t *signature_sz,
                       size_t wait_ms) {

    VS_ASSERT(_prvs_impl.wait_func);

    _reset_last_result();

    // Send request
    if (0 != _send_request(netif, mac, VS_PRVS_ASGN, data, data_sz)) {
        return -1;
    }

    // Wait request
    _prvs_impl.wait_func(wait_ms, &_last_res, RES_UNKNOWN);

    // Pass data
    if (0 == _last_res && _last_data_sz <= buf_sz) {
        memcpy(signature, _last_data, _last_data_sz);
        *signature_sz = _last_data_sz;
        return 0;
    }

    return -1;
}

/******************************************************************************/
int
vs_sdmp_prvs_finalize_tl(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         const uint8_t *data,
                         size_t data_sz,
                         size_t wait_ms) {
    return vs_sdmp_prvs_set(netif, mac, VS_PRVS_TLF, data, data_sz, wait_ms);
}