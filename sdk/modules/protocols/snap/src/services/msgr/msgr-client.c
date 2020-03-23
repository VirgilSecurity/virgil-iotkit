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

#if MSGR_CLIENT
#include <virgil/iot/protocols/snap/msgr/msgr-client.h>
#include <virgil/iot/protocols/snap/msgr/msgr-private.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>

static vs_snap_msgr_client_service_t _impl = {NULL, NULL};
static vs_snap_msgr_device_t *_devices_list = 0;
static size_t _devices_list_max = 0;
static size_t _devices_list_cnt = 0;

/******************************************************************************/
vs_status_e
vs_snap_msgr_enum_devices(const vs_netif_t *netif,
                          vs_snap_msgr_device_t *devices,
                          size_t devices_max,
                          size_t *devices_cnt,
                          uint32_t wait_ms) {
    vs_status_e ret_code;

    // Set storage for ENUM request
    _devices_list = devices;
    _devices_list_max = devices_max;
    _devices_list_cnt = 0;
    *devices_cnt = 0;

    // Normalize byte order
    // Place here if it'll be required

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(netif, 0, VS_MSGR_SERVICE_ID, VS_MSGR_ENUM, NULL, 0), "Cannot send request");

    // Wait request
    vs_impl_msleep(wait_ms);

    *devices_cnt = _devices_list_cnt;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_msgr_set_polling(const vs_netif_t *netif, const vs_mac_addr_t *mac, bool enable, uint16_t period_seconds) {
    vs_msgr_poll_request_t request;
    const vs_netif_t *default_netif = vs_snap_default_netif();
    const vs_mac_addr_t *dst_mac;
    vs_status_e ret_code;

    // Set destination mac
    dst_mac = mac ? mac : vs_snap_broadcast_mac();

    // Fill request fields
    request.enable = enable ? 1 : 0;
    request.period_seconds = period_seconds;
    if (default_netif && default_netif->mac_addr) {
        default_netif->mac_addr(default_netif, &request.recipient_mac);
    } else {
        VS_IOT_MEMSET(request.recipient_mac.bytes, 0xFF, ETH_ADDR_LEN);
    }

    // Normalize byte order
    vs_msgr_poll_request_t_encode(&request);

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(
                             netif, dst_mac, VS_MSGR_SERVICE_ID, VS_MSGR_POLL, (uint8_t *)&request, sizeof(request)),
                     "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_snot_request_processor(const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {
    vs_msgr_enum_response_t *enum_request = (vs_msgr_enum_response_t *)request;
    vs_snap_msgr_device_t device_info;

    // Check is callback present
    if (!_impl.device_start) {
        return VS_CODE_COMMAND_NO_RESPONSE;
    }

    // Check input parameters
    CHECK_RET(request, VS_CODE_ERR_INCORRECT_PARAMETER, "MSGR:SNOT error on a remote device");
    CHECK_RET(sizeof(vs_msgr_enum_response_t) == request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong data size");

    // Get data from packed structure
    VS_IOT_MEMSET(&device_info, 0, sizeof(device_info));
    VS_IOT_MEMCPY(device_info.mac, enum_request->mac.bytes, ETH_ADDR_LEN);

    // Invoke callback
    _impl.device_start(&device_info);

    return VS_CODE_COMMAND_NO_RESPONSE;
}

/******************************************************************************/
static vs_status_e
_stat_request_processor(const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {

    vs_msgr_getd_response_t *stat_request = (vs_msgr_getd_response_t *)request;

    // Check is callback present
    if (!_impl.device_data) {
        return VS_CODE_OK;
    }

    // Check input parameters
    CHECK_RET(request, VS_CODE_ERR_INCORRECT_PARAMETER, "MSGR:STAT error on a remote device");
    CHECK_RET(request_sz >= sizeof(vs_msgr_getd_response_t), VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong data size");

    // Normalize byte order
    vs_msgr_getd_response_t_decode(stat_request);
    CHECK_RET(request_sz == sizeof(vs_msgr_getd_response_t) + stat_request->data_sz,
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Wrong data size");

    // Invoke callback function
    return _impl.device_data(stat_request->data, stat_request->data_sz);
}

/******************************************************************************/
static vs_status_e
_msgr_client_request_processor(const struct vs_netif_t *netif,
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
        return _snot_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_MSGR_STAT:
        return _stat_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_MSGR_POLL:
    case VS_MSGR_SETD:
    case VS_MSGR_GETD:
    case VS_MSGR_ENUM:
        return VS_CODE_COMMAND_NO_RESPONSE;

    default:
        VS_LOG_ERROR("Unsupported MSGR command");
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_getd_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_msgr_getd_response_t *stat_response = (vs_msgr_getd_response_t *)response;

    // Check is callback present
    if (!_impl.device_data) {
        return VS_CODE_OK;
    }

    // Check input parameters
    CHECK_RET(is_ack, VS_CODE_ERR_INCORRECT_PARAMETER, "MSGR:STAT error on a remote device");
    CHECK_RET(response, VS_CODE_ERR_INCORRECT_PARAMETER, "MSGR:STAT error on a remote device");
    CHECK_RET(response_sz >= sizeof(vs_msgr_getd_response_t), VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong data size");

    // Normalize byte order
    vs_msgr_getd_response_t_decode(stat_response);

    CHECK_RET(response_sz == sizeof(vs_msgr_getd_response_t) + stat_response->data_sz,
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Wrong data size");

    // Invoke callback function
    return _impl.device_data(stat_response->data, stat_response->data_sz);
}

/******************************************************************************/
static vs_status_e
_enum_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {

    vs_msgr_enum_response_t *enum_response = (vs_msgr_enum_response_t *)response;

    CHECK_RET(is_ack, VS_CODE_ERR_INCORRECT_PARAMETER, "ENUM error on a remote device");
    CHECK_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT, 0);
    CHECK_RET(sizeof(vs_msgr_enum_response_t) == response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong data size");

    if (_devices_list && _devices_list_cnt < _devices_list_max) {
        VS_IOT_MEMCPY(_devices_list[_devices_list_cnt].mac, enum_response->mac.bytes, ETH_ADDR_LEN);
        _devices_list_cnt++;

        return 0;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_msgr_client_response_processor(const struct vs_netif_t *netif,
                                vs_snap_element_t element_id,
                                bool is_ack,
                                const uint8_t *response,
                                const uint16_t response_sz) {
    (void)netif;

    switch (element_id) {

    case VS_MSGR_SNOT:
    case VS_MSGR_STAT:
        return VS_CODE_COMMAND_NO_RESPONSE;

    case VS_MSGR_ENUM:
        return _enum_response_processor(is_ack, response, response_sz);

    case VS_MSGR_GETD:
        return _getd_response_processor(is_ack, response, response_sz);

    case VS_MSGR_SETD:
    case VS_MSGR_POLL:
        return VS_CODE_OK;

    default:
        VS_LOG_ERROR("Unsupported MSGR command");
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}
/******************************************************************************/
const vs_snap_service_t *
vs_snap_msgr_client(vs_snap_msgr_client_service_t impl) {
    static vs_snap_service_t _msgr;
    VS_IOT_MEMSET(&_msgr, 0, sizeof(_msgr));

    _msgr.user_data = 0;
    _msgr.id = VS_MSGR_SERVICE_ID;
    _msgr.request_process = _msgr_client_request_processor;
    _msgr.response_process = _msgr_client_response_processor;
    _msgr.periodical_process = NULL;

    // Save callbacks
    VS_IOT_MEMCPY(&_impl, &impl, sizeof(impl));

    return &_msgr;
}

#endif