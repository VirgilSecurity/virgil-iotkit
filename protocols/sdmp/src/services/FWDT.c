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

#include <virgil/iot/protocols/sdmp/FWDT.h>
#include <virgil/iot/protocols/sdmp/sdmp_private.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#if !VS_SDMP_FACTORY
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/trust_list/trust_list.h>
#endif // !VS_SDMP_FACTORY

static vs_sdmp_service_t _fwdt_service = {0};
static bool _fwdt_service_ready = false;
static vs_sdmp_fwdt_dnid_list_t *_fwdt_dnid_list = 0;

// External functions for access to upper level implementations
static vs_sdmp_fwdt_impl_t _fwdt_impl = {0};

#define RES_UNKNOWN (-2)
#define RES_NEGATIVE (-1)
#define RES_OK (0)

// Last result
#define FWDT_BUF_SZ (1024)
static int _last_res = RES_UNKNOWN;
static uint16_t _last_data_sz = 0;
static uint8_t _last_data[FWDT_BUF_SZ];

/******************************************************************************/
int
vs_sdmp_fwdt_configure_hal(vs_sdmp_fwdt_impl_t impl) {
    VS_IOT_MEMSET(&_fwdt_impl, 0, sizeof(_fwdt_impl));

    _fwdt_impl.dnid_func = impl.dnid_func;
    _fwdt_impl.wait_func = impl.wait_func;
    _fwdt_impl.stop_wait_func = impl.stop_wait_func;
    return 0;
}

/******************************************************************************/
static int
_fwdt_dnid_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const uint16_t request_sz,
                           uint8_t *response,
                           const uint16_t response_buf_sz,
                           uint16_t *response_sz) {

    vs_sdmp_fwdt_dnid_element_t *dnid_response = (vs_sdmp_fwdt_dnid_element_t *)response;

    VS_IOT_ASSERT(_fwdt_impl.dnid_func);

    if (0 != _fwdt_impl.dnid_func()) {
        return -1;
    }

    const uint16_t required_sz = sizeof(vs_sdmp_fwdt_dnid_element_t);
    VS_IOT_ASSERT(response_buf_sz >= required_sz);

    vs_sdmp_mac_addr(netif, &dnid_response->mac_addr);
    dnid_response->device_type = 0;
    *response_sz = required_sz;

    return 0;
}

/******************************************************************************/
static int
_fwdt_dnid_process_response(const struct vs_netif_t *netif, const uint8_t *response, const uint16_t response_sz) {

    vs_sdmp_fwdt_dnid_element_t *dnid_response = (vs_sdmp_fwdt_dnid_element_t *)response;

    if (_fwdt_dnid_list && _fwdt_dnid_list->count < FWDT_LIST_SZ_MAX) {
        memcpy(&_fwdt_dnid_list->elements[_fwdt_dnid_list->count], dnid_response, sizeof(vs_sdmp_fwdt_dnid_element_t));
        _fwdt_dnid_list->count++;

        return 0;
    }

    return -1;
}

/******************************************************************************/
static int
_fwdt_service_request_processor(const struct vs_netif_t *netif,
                                vs_sdmp_element_t element_id,
                                const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    // Process DNID

    *response_sz = 0;

    switch (element_id) {
    case VS_FWDT_DNID:
        return _fwdt_dnid_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    default:
        VS_IOT_ASSERT(false && "Unsupported command");
    }

    return -1;
}

/******************************************************************************/
static int
_fwdt_service_response_processor(const struct vs_netif_t *netif,
                                 vs_sdmp_element_t element_id,
                                 bool is_ack,
                                 const uint8_t *response,
                                 const uint16_t response_sz) {

    VS_IOT_ASSERT(_fwdt_impl.stop_wait_func);

    switch (element_id) {
    case VS_FWDT_DNID:
        return _fwdt_dnid_process_response(netif, response, response_sz);

    default: {
        if (response_sz && response_sz < FWDT_BUF_SZ) {
            _last_data_sz = response_sz;
            memcpy(_last_data, response, response_sz);
        }

        _fwdt_impl.stop_wait_func(&_last_res, is_ack ? RES_OK : RES_NEGATIVE);

        return 0;
    }
    }
}

/******************************************************************************/
static void
_prepare_fwdt_service() {
    _fwdt_service.user_data = 0;
    _fwdt_service.id = HTONL_IN_COMPILE_TIME('FWDT');
    _fwdt_service.request_process = _fwdt_service_request_processor;
    _fwdt_service.response_process = _fwdt_service_response_processor;
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_fwdt_service() {
    if (!_fwdt_service_ready) {
        _prepare_fwdt_service();
        _fwdt_service_ready = true;
    }

    return &_fwdt_service;
}

/******************************************************************************/
static int
_send_request(const vs_netif_t *netif,
              const vs_mac_addr_t *mac,
              vs_sdmp_fwdt_element_e element,
              const uint8_t *data,
              uint16_t data_sz) {
    uint8_t buffer[sizeof(vs_sdmp_packet_t) + data_sz];
    vs_sdmp_packet_t *packet;

    memset(buffer, 0, sizeof(buffer));

    // Prepare pointers
    packet = (vs_sdmp_packet_t *)buffer;

    // Prepare request
    packet->header.element_id = element;
    packet->header.service_id = _fwdt_service.id;
    packet->header.content_size = data_sz;
    if (data_sz) {
        memcpy(packet->content, data, data_sz);
    }
    _sdmp_fill_header(mac, packet);

    // Send request
    return vs_sdmp_send(netif, buffer, sizeof(vs_sdmp_packet_t) + packet->header.content_size);
}

/******************************************************************************/
int
vs_sdmp_fwdt_uninitialized_devices(const vs_netif_t *netif, vs_sdmp_fwdt_dnid_list_t *list, uint32_t wait_ms) {

    VS_IOT_ASSERT(_fwdt_impl.wait_func);

    // Set storage for DNID request
    _fwdt_dnid_list = list;
    memset(_fwdt_dnid_list, 0, sizeof(*_fwdt_dnid_list));

    // Send request
    if (0 != _send_request(netif, 0, VS_FWDT_DNID, 0, 0)) {
        return -1;
    }

    // Wait request
    vs_global_hal_msleep(wait_ms);

    return 0;
}