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

static vs_snap_cfg_server_service_t _impl = {NULL, NULL, NULL};

/******************************************************************/
static vs_status_e
_conf_wifi_request_processor(const uint8_t *request,
                             const uint16_t request_sz,
                             uint8_t *response,
                             const uint16_t response_buf_sz,
                             uint16_t *response_sz) {
    vs_cfg_conf_wifi_request_t *conf_request = (vs_cfg_conf_wifi_request_t *)request;
    vs_cfg_wifi_configuration_t config_data;

    // Check input parameters
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(request_sz == sizeof(vs_cfg_conf_wifi_request_t),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Unsupported request structure vs_cfg_conf_wifi_request_t");

    if (_impl.wifi_config_cb) {
        VS_IOT_MEMCPY(config_data.ssid, conf_request->ssid, VS_CFG_STR_MAX);
        VS_IOT_MEMCPY(config_data.pass, conf_request->pass, VS_CFG_STR_MAX);
        VS_IOT_MEMCPY(config_data.account, conf_request->account, VS_CFG_STR_MAX);
        _impl.wifi_config_cb(&config_data);
    }

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_conf_messenger_request_processor(const uint8_t *request,
                                  const uint16_t request_sz,
                                  uint8_t *response,
                                  const uint16_t response_buf_sz,
                                  uint16_t *response_sz) {
    vs_cfg_messenger_config_request_t *conf_request = (vs_cfg_messenger_config_request_t *)request;
    vs_cfg_messenger_config_t config_data;

    if (_impl.messenger_config_cb) {
        // Check input parameters
        CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
        CHECK_RET(request_sz == sizeof(vs_cfg_messenger_config_request_t),
                  VS_CODE_ERR_INCORRECT_ARGUMENT,
                  "Unsupported request structure vs_cfg_messenger_config_request_t");


        // Normalize byte order
        vs_cfg_messenger_config_request_t_decode(conf_request);

        VS_IOT_MEMCPY(config_data.enjabberd_host, conf_request->enjabberd_host, sizeof(conf_request->enjabberd_host));
        VS_IOT_MEMCPY(config_data.messenger_base_url,
                      conf_request->messenger_base_url,
                      sizeof(conf_request->messenger_base_url));
        config_data.version = conf_request->version;
        config_data.enjabberd_port = conf_request->enjabberd_port;
        _impl.messenger_config_cb(&config_data);
    }

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_conf_channel_request_processor(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {
    uint8_t i;
    vs_cfg_messenger_channels_request_t *conf_request = (vs_cfg_messenger_channels_request_t *)request;
    vs_cfg_messenger_channels_t config_data;

    if (_impl.channel_config_cb) {
        // Check input parameters
        CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
        CHECK_RET(request_sz == sizeof(vs_cfg_messenger_channels_request_t),
                  VS_CODE_ERR_INCORRECT_ARGUMENT,
                  "Unsupported request structure vs_cfg_messenger_channels_request_t");


        for (i = 0; i < VS_MESSENGER_CHANNEL_NUM_MAX; ++i) {
            VS_IOT_MEMCPY(config_data.channel[i], conf_request->channel[i], VS_MESSENGER_CHANNEL_MAX_SZ);
        }

        config_data.channels_num = conf_request->channels_num;
        _impl.channel_config_cb(&config_data);
    }

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
    case VS_CFG_MSCR:
        return _conf_messenger_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_CFG_MSCH:
        return _conf_channel_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_CFG_WIFI:
        return _conf_wifi_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    default:
        VS_LOG_ERROR("Unsupported _CFG command");
        VS_IOT_ASSERT(false);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_cfg_server(vs_snap_cfg_server_service_t impl) {

    static vs_snap_service_t _cfg;

    _cfg.user_data = NULL;
    _cfg.id = VS_CFG_SERVICE_ID;
    _cfg.request_process = _cfg_request_processor;
    _cfg.response_process = NULL;
    _cfg.periodical_process = NULL;

    // Save callbacks
    VS_IOT_MEMCPY(&_impl, &impl, sizeof(impl));

    return &_cfg;
}

/******************************************************************************/

#endif // CFG_SERVER