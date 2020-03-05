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

#if INFO_SERVER

#if FLDT_CLIENT
#include <virgil/iot/protocols/snap/fldt/fldt-client.h>
#endif

#include <virgil/iot/protocols/snap/info/info-server.h>
#include <virgil/iot/protocols/snap/info/info-private.h>
#include <virgil/iot/protocols/snap/info/info-structs.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include <endian-config.h>

// Polling
typedef struct {
    uint32_t elements_mask;
    uint16_t period_seconds;
    uint16_t time_counter;
    vs_mac_addr_t dest_mac;
} vs_poll_ctx_t;

static vs_snap_info_start_notif_srv_cb_t _startup_notification_cb = NULL;
static vs_poll_ctx_t _poll_ctx = {0, 0, 0, {{0, 0, 0, 0, 0, 0}}};

static vs_file_version_t _firmware_ver = {0, 0, 0, 0, 0};
static vs_file_version_t _tl_ver = {0, 0, 0, 0, 0};

/******************************************************************/
static vs_status_e
_fill_enum_data(vs_info_enum_response_t *enum_data) {
    const vs_netif_t *default_netif;

    // Check input parameters
    CHECK_NOT_ZERO_RET(enum_data, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set MAC address for default network interface
    default_netif = vs_snap_default_netif();
    CHECK_RET(!default_netif->mac_addr(default_netif, &enum_data->mac),
              -1,
              "Cannot get MAC for Default Network Interface");

    // Set current device roles
    enum_data->device_roles = vs_snap_device_roles();

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_enum_request_processing(const uint8_t *request,
                         const uint16_t request_sz,
                         uint8_t *response,
                         const uint16_t response_buf_sz,
                         uint16_t *response_sz) {
    vs_info_enum_response_t *enum_response = (vs_info_enum_response_t *)response;
    vs_status_e ret_code;

    // Check input parameters
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(response_buf_sz > sizeof(vs_info_enum_response_t), VS_CODE_ERR_TOO_SMALL_BUFFER, 0);

    STATUS_CHECK_RET(_fill_enum_data(enum_response), "Cannot fill ENUM data");

    // Set response size
    *response_sz = sizeof(vs_info_enum_response_t);

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_poll_request_processing(const uint8_t *request,
                         const uint16_t request_sz,
                         uint8_t *response,
                         const uint16_t response_buf_sz,
                         uint16_t *response_sz) {

    vs_status_e res = VS_CODE_ERR_INCORRECT_ARGUMENT;
    vs_info_poll_request_t *poll_request = (vs_info_poll_request_t *)request;

    CHECK_NOT_ZERO(request);
    CHECK_NOT_ZERO(response_sz);
    CHECK(sizeof(vs_info_poll_request_t) == request_sz, "Wrong data size");

    // Normalize byte order
    vs_info_poll_request_t_decode(poll_request);

    if (poll_request->enable) {
        _poll_ctx.period_seconds = poll_request->period_seconds;
        _poll_ctx.elements_mask |= poll_request->elements;
        _poll_ctx.time_counter = _poll_ctx.period_seconds;
        VS_IOT_MEMCPY(&_poll_ctx.dest_mac, &poll_request->recipient_mac, sizeof(poll_request->recipient_mac));
    } else {
        _poll_ctx.elements_mask &= ~poll_request->elements;
    }

    *response_sz = 0;

terminate:
    return res;
}

/******************************************************************/
static vs_status_e
_fill_stat_data(vs_info_stat_response_t *stat_data) {
    const vs_netif_t *defautl_netif;
    vs_snap_stat_t stat = vs_snap_get_statistics();

    // Check input parameters
    CHECK_NOT_ZERO_RET(stat_data, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set MAC address for default network interface
    defautl_netif = vs_snap_default_netif();
    CHECK_RET(!defautl_netif->mac_addr(defautl_netif, &stat_data->mac),
              -1,
              "Cannot get MAC for Default Network Interface");

    // Set statistics data
    stat_data->received = stat.received;
    stat_data->sent = stat.sent;

    // Normalize byte order
    vs_info_stat_response_t_encode(stat_data);

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_fill_ginf_data(vs_info_ginf_response_t *general_info) {
    const vs_netif_t *defautl_netif;

    CHECK_NOT_ZERO_RET(general_info, VS_CODE_ERR_INCORRECT_ARGUMENT);

    defautl_netif = vs_snap_default_netif();

    CHECK_RET(!defautl_netif->mac_addr(defautl_netif, &general_info->default_netif_mac),
              -1,
              "Cannot get MAC for Default Network Interface");

    VS_IOT_MEMCPY(general_info->manufacture_id, vs_snap_device_manufacture(), sizeof(vs_device_manufacture_id_t));
    VS_IOT_MEMCPY(general_info->device_type, vs_snap_device_type(), sizeof(vs_device_type_t));
    general_info->fw_version = _firmware_ver;
    general_info->tl_version = _tl_ver;
    general_info->device_roles = vs_snap_device_roles();

    // Normalize byte order
    vs_info_ginf_response_t_encode(general_info);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_snot_request_processor(const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {
    const vs_info_enum_response_t *enum_data = (const vs_info_enum_response_t *)request;
    vs_snap_info_device_t device_info;
    vs_status_e ret_code = VS_CODE_OK;
#if FLDT_CLIENT
    vs_mac_addr_t self_mac;
#endif

    VS_LOG_DEBUG("[INFO:SNOT] Request from device " FLDT_MAC_PRINT_TEMPLATE, FLDT_MAC_PRINT_ARG(enum_data->mac));

    CHECK_NOT_ZERO_RET(enum_data != NULL, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(request_sz == sizeof(*enum_data),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "vs_info_enum_response_t with sizeof=%d has been waited, but actual sizeof=%d",
              sizeof(*enum_data),
              response_sz);

#if FLDT_CLIENT
    STATUS_CHECK_RET(vs_snap_mac_addr(vs_snap_default_netif(), &self_mac), "Unable to request self MAC address");

    if (VS_IOT_MEMCMP(enum_data->mac.bytes, self_mac.bytes, sizeof(self_mac.bytes)) && // different devices
        (vs_snap_device_roles() & VS_SNAP_DEV_THING) &&                                // current device is Thing
        (enum_data->device_roles & VS_SNAP_DEV_GATEWAY)) {                             // sender is Gateway
        ret_code = vs_fldt_client_request_all_files();
        if (ret_code != VS_CODE_OK) {
            VS_LOG_ERROR("[INFO] Unable to request all files update");
        }
    }
#endif

    if (_startup_notification_cb) {
        device_info.device_roles = enum_data->device_roles;
        VS_IOT_MEMCPY(device_info.mac, enum_data->mac.bytes, sizeof(device_info.mac));
        STATUS_CHECK_RET(_startup_notification_cb(&device_info), "Unable to call startup notification callback");
    }

    return ret_code;
};

/******************************************************************************/
static vs_status_e
_info_request_processor(const struct vs_netif_t *netif,
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
        return _enum_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_INFO_POLL:
        return _poll_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_INFO_GINF:
    case VS_INFO_STAT:
        return VS_CODE_COMMAND_NO_RESPONSE;

    default:
        VS_LOG_ERROR("Unsupported INFO command");
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
static vs_status_e
_info_server_periodical_processor(void) {
    vs_status_e ret_code;

    _poll_ctx.time_counter++;
    if (_poll_ctx.time_counter >= _poll_ctx.period_seconds) {
        _poll_ctx.time_counter = 0;
        if (_poll_ctx.elements_mask & VS_SNAP_INFO_GENERAL) {
            vs_info_ginf_response_t general_info;
            STATUS_CHECK_RET(_fill_ginf_data(&general_info), "Error _fill_ginf_data");
            vs_snap_send_request(vs_snap_netif_routing(),
                                 vs_snap_broadcast_mac(),
                                 // &_poll_ctx.dest_mac,
                                 VS_INFO_SERVICE_ID,
                                 VS_INFO_GINF,
                                 (uint8_t *)&general_info,
                                 sizeof(general_info));
        }

        if (_poll_ctx.elements_mask & VS_SNAP_INFO_STATISTICS) {
            vs_info_stat_response_t stat_data;
            STATUS_CHECK_RET(_fill_stat_data(&stat_data), "Cannot fill SNAP statistics");
            vs_snap_send_request(vs_snap_netif_routing(),
                                 vs_snap_broadcast_mac(),
                                 // &_poll_ctx.dest_mac,
                                 VS_INFO_SERVICE_ID,
                                 VS_INFO_STAT,
                                 (uint8_t *)&stat_data,
                                 sizeof(stat_data));
        }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_info_server(vs_snap_info_start_notif_srv_cb_t startup_cb) {

    static vs_snap_service_t _info = {0};

    _startup_notification_cb = startup_cb;

    _info.user_data = NULL;
    _info.id = VS_INFO_SERVICE_ID;
    _info.request_process = _info_request_processor;
    _info.response_process = NULL;
    _info.periodical_process = _info_server_periodical_processor;
    //    _info.deinit =

    return &_info;
}

/******************************************************************************/
vs_status_e
vs_snap_info_start_notification(const vs_netif_t *netif) {
    vs_info_enum_response_t enum_data;
    vs_status_e ret_code;

    STATUS_CHECK_RET(_fill_enum_data(&enum_data), "Cannot fill ENUM data");

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(netif,
                                          vs_snap_broadcast_mac(),
                                          VS_INFO_SERVICE_ID,
                                          VS_INFO_SNOT,
                                          (uint8_t *)&enum_data,
                                          sizeof(enum_data)),
                     "Cannot send data");

    return VS_CODE_OK;
}

/******************************************************************************/
void
vs_snap_info_set_firmware_ver(vs_file_version_t ver) {
    _firmware_ver = ver;
}

/******************************************************************************/
void
vs_snap_info_set_tl_ver(vs_file_version_t ver) {
    _tl_ver = ver;
}

/******************************************************************************/

#endif // INFO_SERVER