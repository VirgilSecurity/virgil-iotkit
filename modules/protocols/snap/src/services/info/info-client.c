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

#if INFO_CLIENT

#include <virgil/iot/protocols/snap/info/info-client.h>
#include <virgil/iot/protocols/snap/info/info-private.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>
#include <stdlib-config.h>
#include <global-hal.h>

// External functions for access to upper level implementations
static vs_snap_service_t _info_client = {0};

static vs_snap_info_device_t *_devices_list = 0;
static size_t _devices_list_max = 0;
static size_t _devices_list_cnt = 0;

// Callbacks for devices polling
static vs_snap_info_client_service_t _impl = {NULL, NULL, NULL};

/******************************************************************************/
vs_status_e
vs_snap_info_enum_devices(const vs_netif_t *netif,
                          vs_snap_info_device_t *devices,
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
    STATUS_CHECK_RET(vs_snap_send_request(netif, 0, VS_INFO_SERVICE_ID, VS_INFO_ENUM, NULL, 0), "Cannot send request");

    // Wait request
    vs_impl_msleep(wait_ms);

    *devices_cnt = _devices_list_cnt;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_info_set_polling(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         uint32_t elements, // Multiple vs_snap_info_element_mask_e
                         bool enable,
                         uint16_t period_seconds) {
    vs_info_poll_request_t request;
    const vs_netif_t *default_netif = vs_snap_default_netif();
    const vs_mac_addr_t *dst_mac;
    vs_status_e ret_code;

    // Set destination mac
    dst_mac = mac ? mac : vs_snap_broadcast_mac();

    // Fill request fields
    request.elements = elements;
    request.enable = enable ? 1 : 0;
    request.period_seconds = period_seconds;
    if (default_netif && default_netif->mac_addr) {
        default_netif->mac_addr(default_netif, &request.recipient_mac);
    } else {
        VS_IOT_MEMSET(request.recipient_mac.bytes, 0xFF, ETH_ADDR_LEN);
    }

    // Normalize byte order
    vs_info_poll_request_t_encode(&request);

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(
                             netif, dst_mac, VS_INFO_SERVICE_ID, VS_INFO_POLL, (uint8_t *)&request, sizeof(request)),
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
    vs_info_enum_response_t *enum_request = (vs_info_enum_response_t *)request;
    vs_snap_info_device_t device_info;

    // Check is callback present
    if (!_impl.device_start) {
        return VS_CODE_COMMAND_NO_RESPONSE;
    }

    // Check input parameters
    CHECK_RET(request, VS_CODE_ERR_INCORRECT_PARAMETER, "SNAP:SNOT error on a remote device");
    CHECK_RET(sizeof(vs_info_enum_response_t) == request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong data size");

    // Get data from packed structure
    VS_IOT_MEMSET(&device_info, 0, sizeof(device_info));
    VS_IOT_MEMCPY(device_info.mac, enum_request->mac.bytes, ETH_ADDR_LEN);
    device_info.device_roles = enum_request->device_roles;

    // Invoke callback
    _impl.device_start(&device_info);

    return VS_CODE_COMMAND_NO_RESPONSE;
}

/******************************************************************************/
static vs_status_e
_ginf_request_processor(const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {

    vs_info_ginf_response_t *ginf_request = (vs_info_ginf_response_t *)request;
    vs_info_general_t general_info;

    // Check is callback present
    if (!_impl.general_info) {
        return VS_CODE_OK;
    }

    // Normalize byte order
    vs_info_ginf_response_t_decode(ginf_request);

    // Check input parameters
    CHECK_RET(request, VS_CODE_ERR_INCORRECT_PARAMETER, "SNAP:GINF error on a remote device");
    CHECK_RET(sizeof(vs_info_ginf_response_t) == request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong data size");

    // Get data from packed structure
    VS_IOT_MEMSET(&general_info, 0, sizeof(general_info));
    VS_IOT_MEMCPY(general_info.manufacture_id, ginf_request->manufacture_id, VS_DEVICE_MANUFACTURE_ID_SIZE);
    VS_IOT_MEMCPY(general_info.device_type, ginf_request->device_type, VS_DEVICE_TYPE_SIZE);
    VS_IOT_MEMCPY(general_info.default_netif_mac, ginf_request->default_netif_mac.bytes, ETH_ADDR_LEN);

    // Firmware version
    general_info.fw_ver.major = ginf_request->fw_version.major;
    general_info.fw_ver.minor = ginf_request->fw_version.minor;
    general_info.fw_ver.patch = ginf_request->fw_version.patch;
    general_info.fw_ver.build = ginf_request->fw_version.build;
    general_info.fw_ver.timestamp = ginf_request->fw_version.timestamp;

    // TrustList version
    general_info.tl_ver.major = ginf_request->tl_version.major;
    general_info.tl_ver.minor = ginf_request->tl_version.minor;
    general_info.tl_ver.patch = ginf_request->tl_version.patch;
    general_info.tl_ver.build = ginf_request->tl_version.build;
    general_info.tl_ver.timestamp = ginf_request->tl_version.timestamp;
    general_info.device_roles = ginf_request->device_roles;

    // Invoke callback function
    _impl.general_info(&general_info);

    *response_sz = 0;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_stat_request_processor(const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {

    vs_info_stat_response_t *stat_request = (vs_info_stat_response_t *)request;
    vs_info_statistics_t stat_info;

    // Check is callback present
    if (!_impl.statistics) {
        return VS_CODE_OK;
    }

    // Normalize byte order
    vs_info_stat_response_t_decode(stat_request);

    // Check input parameters
    CHECK_RET(request, VS_CODE_ERR_INCORRECT_PARAMETER, "SNAP:STAT error on a remote device");
    CHECK_RET(sizeof(vs_info_stat_response_t) == request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong data size");

    // Get data from packed structure
    VS_IOT_MEMSET(&stat_info, 0, sizeof(stat_info));
    VS_IOT_MEMCPY(stat_info.default_netif_mac, stat_request->mac.bytes, ETH_ADDR_LEN);
    stat_info.received = stat_request->received;
    stat_info.sent = stat_request->sent;

    // Invoke callback function
    _impl.statistics(&stat_info);

    *response_sz = 0;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_enum_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {

    vs_info_enum_response_t *enum_response = (vs_info_enum_response_t *)response;

    CHECK_RET(is_ack, VS_CODE_ERR_INCORRECT_PARAMETER, "ENUM error on a remote device");
    CHECK_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT, 0);
    CHECK_RET(sizeof(vs_info_enum_response_t) == response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong data size");

    if (_devices_list && _devices_list_cnt < _devices_list_max) {
        VS_IOT_MEMCPY(_devices_list[_devices_list_cnt].mac, enum_response->mac.bytes, ETH_ADDR_LEN);
        _devices_list[_devices_list_cnt].device_roles = enum_response->device_roles;
        _devices_list_cnt++;

        return 0;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_poll_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_info_client_request_processor(const struct vs_netif_t *netif,
                               vs_snap_element_t element_id,
                               const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {
    (void)netif;

    *response_sz = 0;

    switch (element_id) {

    case VS_INFO_SNOT:
        return _snot_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_INFO_ENUM:
    case VS_INFO_POLL:
        return VS_CODE_COMMAND_NO_RESPONSE;

    case VS_INFO_GINF:
        return _ginf_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_INFO_STAT:
        return _stat_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    default:
        VS_LOG_ERROR("Unsupported INFO command");
        VS_IOT_ASSERT(false);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
static vs_status_e
_info_client_response_processor(const struct vs_netif_t *netif,
                                vs_snap_element_t element_id,
                                bool is_ack,
                                const uint8_t *response,
                                const uint16_t response_sz) {
    (void)netif;

    switch (element_id) {

    case VS_INFO_SNOT:
    case VS_INFO_GINF:
    case VS_INFO_STAT:
        return VS_CODE_COMMAND_NO_RESPONSE;

    case VS_INFO_ENUM:
        return _enum_response_processor(is_ack, response, response_sz);

    case VS_INFO_POLL:
        return _poll_response_processor(is_ack, response, response_sz);

    default:
        VS_LOG_ERROR("Unsupported INFO command");
        VS_IOT_ASSERT(false);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_info_client(vs_snap_info_client_service_t impl) {

    _info_client.user_data = 0;
    _info_client.id = VS_INFO_SERVICE_ID;
    _info_client.request_process = _info_client_request_processor;
    _info_client.response_process = _info_client_response_processor;
    _info_client.periodical_process = NULL;

    // Save callbacks
    VS_IOT_MEMCPY(&_impl, &impl, sizeof(impl));

    return &_info_client;
}

/******************************************************************************/

#endif // INFO_CLIENT
