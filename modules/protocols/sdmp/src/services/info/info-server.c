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

#if INFO_SERVER

#include <virgil/iot/protocols/sdmp/info/info-server.h>
#include <virgil/iot/protocols/sdmp/info/info-private.h>
#include <virgil/iot/protocols/sdmp/info/info-structs.h>
#include <virgil/iot/protocols/sdmp/generated/sdmp_cvt.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include <endian-config.h>

// Commands

static vs_storage_op_ctx_t *_tl_ctx;
static vs_storage_op_ctx_t *_fw_ctx;
#define FW_DESCR_BUF 128

// Polling
typedef struct {
    uint32_t elements_mask;
    uint16_t period_seconds;
    uint16_t time_counter;
    vs_mac_addr_t dest_mac;
} vs_poll_ctx_t;

static vs_poll_ctx_t _poll_ctx = {0, 0, 0};

/******************************************************************/
static vs_status_e
_fill_enum_data(vs_info_enum_response_t *enum_data) {
    const vs_netif_t *default_netif;

    // Check input parameters
    CHECK_NOT_ZERO_RET(enum_data, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set MAC address for default network interface
    default_netif = vs_sdmp_default_netif();
    CHECK_RET(!default_netif->mac_addr(&enum_data->mac), -1, "Cannot get MAC for Default Network Interface");

    // Set current device roles
    enum_data->device_roles = vs_sdmp_device_roles();

    // Normalize byte order
    vs_info_enum_response_t_encode(enum_data);

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

    VS_LOG_DEBUG("[info] poll request. en = %d, period = %d, mask = %08x, time = %d",
                 poll_request->enable,
                 poll_request->period_seconds,
                 poll_request->elements,
                 poll_request->period_seconds);
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
    vs_sdmp_stat_t stat = vs_sdmp_get_statistics();

    // Check input parameters
    CHECK_NOT_ZERO_RET(stat_data, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set MAC address for default network interface
    defautl_netif = vs_sdmp_default_netif();
    CHECK_RET(!defautl_netif->mac_addr(&stat_data->mac), -1, "Cannot get MAC for Default Network Interface");

    // Set statistics data
    stat_data->received = stat.received;
    stat_data->sent = stat.sent;

    VS_LOG_DEBUG("[INFO] Send statistics: sent = %lu, received = %lu",
                 (unsigned long)stat_data->sent,
                 (unsigned long)stat_data->received);

    // Normalize byte order
    vs_info_stat_response_t_encode(stat_data);

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_stat_request_processing(const uint8_t *request,
                         const uint16_t request_sz,
                         uint8_t *response,
                         const uint16_t response_buf_sz,
                         uint16_t *response_sz) {

    vs_status_e ret_code = VS_CODE_ERR_INCORRECT_ARGUMENT;
    vs_info_stat_response_t *stat = (vs_info_stat_response_t *)response;

    CHECK_NOT_ZERO(request);
    CHECK_NOT_ZERO(response_sz);
    CHECK(response_buf_sz >= sizeof(vs_info_stat_response_t), "Wrong data size");

    STATUS_CHECK_RET(_fill_stat_data(stat), "Cannot fill SDMP statistics");

    *response_sz = sizeof(*stat);
    ret_code = VS_CODE_OK;

terminate:

    return ret_code;
}

/******************************************************************/
static vs_status_e
_fill_ginf_data(vs_info_ginf_response_t *general_info) {
    vs_firmware_descriptor_t fw_descr;
    const vs_netif_t *defautl_netif;
    vs_tl_element_info_t tl_elem_info;
    vs_tl_header_t tl_header;
    uint16_t tl_header_sz = sizeof(tl_header);
    vs_status_e ret_code;
    char filever_descr[FW_DESCR_BUF];

    CHECK_NOT_ZERO_RET(general_info, VS_CODE_ERR_INCORRECT_ARGUMENT);

    defautl_netif = vs_sdmp_default_netif();

    CHECK_RET(!defautl_netif->mac_addr(&general_info->default_netif_mac),
              -1,
              "Cannot get MAC for Default Network Interface");

    STATUS_CHECK_RET(vs_firmware_get_own_firmware_descriptor(&fw_descr), "Unable to get own firmware descriptor");

    tl_elem_info.id = VS_TL_ELEMENT_TLH;
    STATUS_CHECK_RET(vs_tl_load_part(&tl_elem_info, (uint8_t *)&tl_header, tl_header_sz, &tl_header_sz),
                     "Unable to obtain Trust List version");
    vs_tl_header_to_host(&tl_header, &tl_header);

    VS_IOT_MEMCPY(general_info->manufacture_id, vs_sdmp_device_manufacture(), sizeof(vs_device_manufacture_id_t));
    VS_IOT_MEMCPY(general_info->device_type, vs_sdmp_device_type(), sizeof(vs_device_type_t));
    VS_IOT_MEMCPY(&general_info->fw_version, &fw_descr.info.version, sizeof(fw_descr.info.version));
    VS_IOT_MEMCPY(&general_info->tl_version, &tl_header.version, sizeof(tl_header.version));
    general_info->device_roles = vs_sdmp_device_roles();

    VS_LOG_DEBUG(
            "[INFO] Send current information: manufacture id = \"%s\", device type = \"%c%c%c%c\", firmware version = "
            "%s, trust list "
            "version = %d.%d.%d.%d",
            general_info->manufacture_id,
            general_info->device_type[0],
            general_info->device_type[1],
            general_info->device_type[2],
            general_info->device_type[3],
            vs_firmware_describe_version(&general_info->fw_version, filever_descr, sizeof(filever_descr)),
            general_info->tl_version.major,
            general_info->tl_version.minor,
            general_info->tl_version.patch,
            general_info->tl_version.build);

    // Normalize byte order
    vs_info_ginf_response_t_encode(general_info);

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_ginf_request_processing(const uint8_t *request,
                         const uint16_t request_sz,
                         uint8_t *response,
                         const uint16_t response_buf_sz,
                         uint16_t *response_sz) {
    vs_info_ginf_response_t *general_info = (vs_info_ginf_response_t *)response;
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(response_buf_sz > sizeof(vs_info_ginf_response_t), VS_CODE_ERR_TOO_SMALL_BUFFER, 0);

    STATUS_CHECK_RET(_fill_ginf_data(general_info), 0);

    *response_sz = sizeof(vs_info_ginf_response_t);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_info_request_processor(const struct vs_netif_t *netif,
                        vs_sdmp_element_t element_id,
                        const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {
    (void)netif;

    *response_sz = 0;

    if (request_sz) {
        VS_LOG_HEX(VS_LOGLEV_DEBUG, "[info] packet debug = ", request, request_sz);
    } else {
        VS_LOG_DEBUG("[info] Empty  packet");
    }

    switch (element_id) {

    case VS_INFO_SNOT:
        return VS_CODE_COMMAND_NO_RESPONSE;

    case VS_INFO_ENUM:
        return _enum_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_INFO_POLL:
        return _poll_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_INFO_GINF:
        return _ginf_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_INFO_STAT:
        return _stat_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    default:
        VS_LOG_ERROR("Unsupported INFO command");
        VS_IOT_ASSERT(false);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
static vs_status_e
_info_server_periodical_processor(void) {
    vs_status_e ret_code;

    static bool started = false;

    // Send broadcast notification about self start
    if (!started) {
        started = true;
        vs_sdmp_info_start_notification(NULL);
    }

    _poll_ctx.time_counter++;
    if (_poll_ctx.time_counter >= _poll_ctx.period_seconds) {
        _poll_ctx.time_counter = 0;
        if (_poll_ctx.elements_mask & VS_SDMP_INFO_GENERAL) {
            vs_info_ginf_response_t general_info;
            STATUS_CHECK_RET(_fill_ginf_data(&general_info), 0);
            vs_sdmp_send_request(NULL,
                                 &_poll_ctx.dest_mac,
                                 VS_INFO_SERVICE_ID,
                                 VS_INFO_GINF,
                                 (uint8_t *)&general_info,
                                 sizeof(general_info));
        }

        if (_poll_ctx.elements_mask & VS_SDMP_INFO_STATISTICS) {
            vs_info_stat_response_t stat_data;
            STATUS_CHECK_RET(_fill_stat_data(&stat_data), "Cannot fill SDMP statistics");
            vs_sdmp_send_request(NULL,
                                 &_poll_ctx.dest_mac,
                                 VS_INFO_SERVICE_ID,
                                 VS_INFO_STAT,
                                 (uint8_t *)&stat_data,
                                 sizeof(stat_data));
        }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_info_server(vs_storage_op_ctx_t *tl_ctx, vs_storage_op_ctx_t *fw_ctx) {

    static vs_sdmp_service_t _info = {0};

    CHECK_NOT_ZERO_RET(tl_ctx, NULL);
    CHECK_NOT_ZERO_RET(fw_ctx, NULL);

    _tl_ctx = tl_ctx;
    _fw_ctx = fw_ctx;

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
vs_sdmp_info_start_notification(const vs_netif_t *netif) {
    vs_info_enum_response_t enum_data;
    vs_status_e ret_code;

    STATUS_CHECK_RET(_fill_enum_data(&enum_data), "Cannot fill ENUM data");

    // Send request
    STATUS_CHECK_RET(vs_sdmp_send_request(netif,
                                          vs_sdmp_broadcast_mac(),
                                          VS_INFO_SERVICE_ID,
                                          VS_INFO_SNOT,
                                          (uint8_t *)&enum_data,
                                          sizeof(enum_data)),
                     "Cannot send data");

    return VS_CODE_OK;
}

/******************************************************************************/

#endif // INFO_SERVER