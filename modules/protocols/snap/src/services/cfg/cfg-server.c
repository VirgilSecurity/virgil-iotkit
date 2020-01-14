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

#if CFG_SERVER

#include <virgil/iot/protocols/snap/cfg/cfg-server.h>
#include <virgil/iot/protocols/snap/cfg/cfg-private.h>
#include <virgil/iot/protocols/snap/cfg/cfg-structs.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include <endian-config.h>

static vs_snap_cfg_config_cb_t _config_cb = NULL;

/******************************************************************/
static vs_status_e
_conf_request_processor(const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {
    vs_cfg_conf_request_t *conf_request = (vs_cfg_conf_request_t *)request;
    vs_cfg_configuration_t config_data;

    // Check input parameters
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(request_sz == sizeof(vs_cfg_conf_request_t),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Unsupported request structure vs_cfg_conf_request_t");

    if (_config_cb) {
        VS_IOT_MEMCPY(config_data.ssid, conf_request->ssid, VS_CFG_STR_MAX);
        VS_IOT_MEMCPY(config_data.pass, conf_request->pass, VS_CFG_STR_MAX);
        VS_IOT_MEMCPY(config_data.account, conf_request->account, VS_CFG_STR_MAX);
        _config_cb(&config_data);
    }

    // Set response size
    *response_sz = 0;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_cfg_request_processor(const struct vs_netif_t *netif,
                       vs_snap_element_t element_id,
                       const uint8_t *request,
                       const uint16_t request_sz,
                       uint8_t *response,
                       const uint16_t response_buf_sz,
                       uint16_t *response_sz) {
    (void)netif;

    *response_sz = 0;

    switch (element_id) {

    case VS_CFG_CONF:
        return _conf_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    default:
        VS_LOG_ERROR("Unsupported _CFG command");
        VS_IOT_ASSERT(false);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_cfg_server(vs_snap_cfg_config_cb_t config_cb) {

    static vs_snap_service_t _info;

    _config_cb = config_cb;

    _info.user_data = NULL;
    _info.id = VS_CFG_SERVICE_ID;
    _info.request_process = _cfg_request_processor;
    _info.response_process = NULL;
    _info.periodical_process = NULL;
    return &_info;
}

/******************************************************************************/

#endif // CFG_SERVER