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

#if MSGR_SERVER
#include <virgil/iot/protocols/snap/msgr/msgr-server.h>
#include <virgil/iot/protocols/snap/msgr/msgr-private.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>

#define GETD_RESPONSE_SZ_MAX (sizeof(vs_msgr_getd_response_t) + 1024)
// Polling
typedef struct {
    bool enable;
    uint16_t period_seconds;
    uint16_t time_counter;
    vs_mac_addr_t dest_mac;
} vs_poll_ctx_t;

static vs_snap_msgr_server_service_t _impl = {NULL, NULL};
static vs_poll_ctx_t _poll_ctx = {0, 0, 0, {{0, 0, 0, 0, 0, 0}}};

/******************************************************************/
static vs_status_e
_fill_enum_data(vs_msgr_enum_response_t *enum_data) {
    const vs_netif_t *default_netif;

    // Check input parameters
    CHECK_NOT_ZERO_RET(enum_data, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set MAC address for default network interface
    default_netif = vs_snap_default_netif();
    CHECK_RET(!default_netif->mac_addr(default_netif, &enum_data->mac),
              -1,
              "Cannot get MAC for Default Network Interface");

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_getd_request_processing(const uint8_t *request,
                         const uint16_t request_sz,
                         uint8_t *response,
                         const uint16_t response_buf_sz,
                         uint16_t *response_sz) {
    vs_status_e res = VS_CODE_ERR_INCORRECT_ARGUMENT;
    vs_msgr_getd_response_t *stat = (vs_msgr_getd_response_t *)response;
    uint32_t data_sz;

    CHECK_NOT_ZERO(response);
    CHECK_NOT_ZERO(response_sz);
    CHECK_NOT_ZERO(_impl.get_data);
    CHECK(response_buf_sz > sizeof(vs_msgr_getd_response_t), "Wrong data size");

    STATUS_CHECK(_impl.get_data(stat->data, response_buf_sz - sizeof(vs_msgr_getd_response_t), &data_sz),
                 "Error get data");
    stat->data_sz = data_sz;
    *response_sz = data_sz + sizeof(vs_msgr_getd_response_t);

    // Normalize byte order
    vs_msgr_getd_response_t_encode(stat);

terminate:
    return res;
}

/******************************************************************************/
static vs_status_e
_setd_request_processing(const uint8_t *request,
                         const uint16_t request_sz,
                         uint8_t *response,
                         const uint16_t response_buf_sz,
                         uint16_t *response_sz) {
    vs_status_e res = VS_CODE_ERR_INCORRECT_ARGUMENT;
    vs_msgr_setd_request_t *setd = (vs_msgr_setd_request_t *)response;

    CHECK_NOT_ZERO(request);
    CHECK_NOT_ZERO(response_sz);
    CHECK_NOT_ZERO(_impl.set_data);
    CHECK(request_sz >= sizeof(vs_msgr_setd_request_t), "Wrong data size");

    vs_msgr_setd_request_t_decode(setd);

    CHECK_RET(request_sz == sizeof(vs_msgr_setd_request_t) + setd->data_sz,
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Wrong data size");

    STATUS_CHECK(_impl.set_data(setd->data, setd->data_sz), "Error set data");

terminate:
    return res;
}

/******************************************************************/
static vs_status_e
_enum_request_processing(const uint8_t *request,
                         const uint16_t request_sz,
                         uint8_t *response,
                         const uint16_t response_buf_sz,
                         uint16_t *response_sz) {
    vs_msgr_enum_response_t *enum_response = (vs_msgr_enum_response_t *)response;
    vs_status_e ret_code;

    // Check input parameters
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(response_buf_sz > sizeof(vs_msgr_enum_response_t), VS_CODE_ERR_TOO_SMALL_BUFFER, 0);

    STATUS_CHECK_RET(_fill_enum_data(enum_response), "Cannot fill ENUM data");

    // Set response size
    *response_sz = sizeof(vs_msgr_enum_response_t);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_poll_request_processing(const uint8_t *request,
                         const uint16_t request_sz,
                         uint8_t *response,
                         const uint16_t response_buf_sz,
                         uint16_t *response_sz) {
    vs_status_e res = VS_CODE_ERR_INCORRECT_ARGUMENT;
    vs_msgr_poll_request_t *poll_request = (vs_msgr_poll_request_t *)request;

    CHECK_NOT_ZERO(request);
    CHECK_NOT_ZERO(response_sz);
    CHECK(sizeof(vs_msgr_poll_request_t) == request_sz, "Wrong data size");

    // Normalize byte order
    vs_msgr_poll_request_t_decode(poll_request);

    _poll_ctx.enable = poll_request->enable;
    _poll_ctx.period_seconds = poll_request->period_seconds;
    _poll_ctx.time_counter = _poll_ctx.period_seconds;
    VS_IOT_MEMCPY(&_poll_ctx.dest_mac, &poll_request->recipient_mac, sizeof(poll_request->recipient_mac));

terminate:
    return res;
}

/******************************************************************************/
static vs_status_e
_msgr_request_processor(const struct vs_netif_t *netif,
                        vs_snap_element_t element_id,
                        const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {
    (void)netif;

    *response_sz = 0;

    switch (element_id) {

    case VS_MSGR_SNOT:
    case VS_MSGR_STAT:
        return VS_CODE_COMMAND_NO_RESPONSE;

    case VS_MSGR_ENUM:
        return _enum_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_MSGR_GETD:
        return _getd_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_MSGR_SETD:
        return _setd_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_MSGR_POLL:
        return _poll_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    default:
        VS_LOG_ERROR("Unsupported MSGR command");
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
static vs_status_e
_msgr_server_periodical_processor(void) {
    vs_status_e ret_code;

    if (!_impl.get_data || !_poll_ctx.enable) {
        return VS_CODE_OK;
    }
    _poll_ctx.time_counter++;
    if (_poll_ctx.time_counter >= _poll_ctx.period_seconds) {
        _poll_ctx.time_counter = 0;
        uint8_t buf[GETD_RESPONSE_SZ_MAX];
        uint32_t data_sz;
        vs_msgr_getd_response_t *stat = (vs_msgr_getd_response_t *)buf;
        STATUS_CHECK_RET(_impl.get_data(stat->data, sizeof(buf) - sizeof(vs_msgr_getd_response_t), &data_sz),
                         "Error get data");
        stat->data_sz = data_sz;

        // Normalize byte order
        vs_msgr_getd_response_t_encode(stat);

        vs_snap_send_request(vs_snap_netif_routing(),
                             vs_snap_broadcast_mac(),
                             VS_MSGR_SERVICE_ID,
                             VS_MSGR_STAT,
                             buf,
                             data_sz + sizeof(vs_msgr_getd_response_t));
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_msgr_start_notification(const vs_netif_t *netif) {
    vs_msgr_enum_response_t enum_data;
    vs_status_e ret_code;

    STATUS_CHECK_RET(_fill_enum_data(&enum_data), "Cannot fill ENUM data");

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(netif,
                                          vs_snap_broadcast_mac(),
                                          VS_MSGR_SERVICE_ID,
                                          VS_MSGR_SNOT,
                                          (uint8_t *)&enum_data,
                                          sizeof(enum_data)),
                     "Cannot send data");

    return VS_CODE_OK;
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_msgr_server(vs_snap_msgr_server_service_t impl) {

    static vs_snap_service_t _msgr;
    VS_IOT_MEMSET(&_msgr, 0, sizeof(_msgr));

    _msgr.user_data = NULL;
    _msgr.id = VS_MSGR_SERVICE_ID;
    _msgr.request_process = _msgr_request_processor;
    _msgr.response_process = NULL;
    _msgr.periodical_process = _msgr_server_periodical_processor;

    // Save callbacks
    VS_IOT_MEMCPY(&_impl, &impl, sizeof(impl));

    return &_msgr;
}

#endif
