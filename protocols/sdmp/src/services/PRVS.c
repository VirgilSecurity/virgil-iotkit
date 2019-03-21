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
#include "hal/macro.h"
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static vs_sdmp_service_t _prvs_service = {0};
static bool _prvs_service_ready = false;
static vs_sdmp_prvs_dnid_t _prvs_dnid_func = 0;
static vs_sdmp_prvs_dnid_list_t *_prvs_dnid_list = 0;

/******************************************************************************/
int
vs_sdmp_prvs_configure_hal(vs_sdmp_prvs_dnid_t dnid_func) {
    VS_ASSERT(dnid_func);
    _prvs_dnid_func = dnid_func;
    return 0;
}

/******************************************************************************/
static int
_prvs_dnid_process_request(const struct vs_netif_t *netif, const uint8_t *request, const size_t request_sz,
        uint8_t *response, const size_t response_buf_sz, size_t *response_sz) {

    vs_sdmp_element_data_t *sdmp_data = (vs_sdmp_element_data_t *)response;
    vs_sdmp_prvs_dnid_element_t *dnid_response = (vs_sdmp_prvs_dnid_element_t *)sdmp_data->data.data;
    sdmp_data->data.len = sizeof(vs_sdmp_prvs_dnid_element_t);
    sdmp_data->element_id = VS_PRVS_DNID;

#if 0
    VS_ASSERT(_prvs_dnid_func);
#endif
    const size_t required_sz = sizeof(vs_sdmp_element_data_t) + sizeof(vs_sdmp_prvs_dnid_element_t);
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
_prvs_service_request_processor(const struct vs_netif_t *netif, const uint8_t *request, const size_t request_sz,
        uint8_t *response, const size_t response_buf_sz, size_t *response_sz) {

    int res = -1;
    vs_sdmp_element_data_t *sdmp_data = (vs_sdmp_element_data_t *)request;

    // Process DNID
    if (VS_PRVS_DNID == sdmp_data->element_id) {
        res = _prvs_dnid_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);
    }

    // Prepare response;
    if (0 == res) {
    }

    return res;
}

/******************************************************************************/
static int
_prvs_service_response_processor(const struct vs_netif_t *netif, const uint8_t *response, const size_t response_sz) {
    int res = -1;
    vs_sdmp_element_data_t *sdmp_data = (vs_sdmp_element_data_t *)response;

    // Process DNID
    if (VS_PRVS_DNID == sdmp_data->element_id) {
        res = _prvs_dnid_process_response(netif, sdmp_data->data.data, sdmp_data->data.len);
    }

    return res;
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
int
vs_sdmp_prvs_uninitialized_devices(const vs_netif_t *netif, vs_sdmp_prvs_dnid_list_t *list, size_t wait_ms) {

    uint8_t buffer[sizeof(vs_sdmp_packet_t) + sizeof(vs_sdmp_element_data_t)];
    vs_sdmp_packet_t *packet;
    vs_sdmp_element_data_t *content;

    // Check input parameters
    VS_ASSERT(list);

    memset(buffer, 0, sizeof(buffer));

    // Prepare pointers
    packet = (vs_sdmp_packet_t *)buffer;
    content = (vs_sdmp_element_data_t *)packet->content;

    // Prepare request
    content->element_id = VS_PRVS_DNID;
    content->data.len = 0;

    packet->header.service_id = _prvs_service.id;
    packet->header.content_size = sizeof(vs_sdmp_element_data_t);

    _sdmp_fill_header(0, packet);

    // Set storage for DNID request
    _prvs_dnid_list = list;

    // Send request
    if (0 != vs_sdmp_send(netif, buffer, sizeof(vs_sdmp_packet_t) + packet->header.content_size)) {
        return -1;
    }

    // Wait request
    usleep(wait_ms * 1000);

    return 0;
}

/******************************************************************************/
int
vs_sdmp_prvs_device_info() {
    return -1;
}

/******************************************************************************/
int
vs_sdmp_prvs_sign_data() {
    return -1;
}

/******************************************************************************/
int
vs_sdmp_prvs_set(vs_sdmp_prvs_element_t element, const uint8_t *data, size_t data_sz) {
    return -1;
}

/******************************************************************************/
int
vs_sdmp_prvs_get(vs_sdmp_prvs_element_t element, uint8_t *data, size_t buf_sz, size_t *data_sz) {
    return -1;
}