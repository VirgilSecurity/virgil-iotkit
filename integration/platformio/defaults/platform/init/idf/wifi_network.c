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


#include <platform/init/idf/wifi_network.h>
#include "nvs.h"

static EventGroupHandle_t s_wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;
static int s_retry_num = 0;
static wifi_status_cb_t _wifi_status_cb = NULL;

static const char *SSID_KEY = "ssid_key";
static const char *PASS_KEY = "pass_key";
static const char *NVS_WIFI = "NVS_WIFI";

static esp_err_t
_wifi_creds_load(uint8_t ssid[SSID_SZ], uint8_t pass[PASS_SZ]);

//******************************************************************************
static esp_err_t
event_handler(void *ctx, system_event_t *event) {
    switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        VS_LOG_INFO("got ip:%s", ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        if (_wifi_status_cb) {
            _wifi_status_cb(true);
        }
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED: {
        VS_LOG_INFO("connect to the AP fail");

        if (s_retry_num < ESP_WIFI_MAXIMUM_RETRY) {
            esp_wifi_connect();
            xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
            s_retry_num++;
            VS_LOG_INFO("retry to connect to the AP");
        } else {
            if (_wifi_status_cb) {
                _wifi_status_cb(false);
            }
        }

        break;
    }
    default:
        break;
    }
    return ESP_OK;
}

//******************************************************************************

#if 0
esp_err_t
wifi_init_sta(wifi_status_cb_t cb) {
#endif
esp_err_t
wifi_init_sta(wifi_status_cb_t cb, wifi_config_t wifi_config) {
#if 0
    wifi_config_t wifi_config;
#endif
    esp_err_t ret_res = ESP_FAIL;
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    s_wifi_event_group = xEventGroupCreate();

    _wifi_status_cb = cb;

#if 0
    memset(&wifi_config, 0, sizeof(wifi_config_t));
    INIT_STATUS_CHECK(ret_res = _wifi_creds_load(wifi_config.sta.ssid, wifi_config.sta.password),
                      "Cannot load WiFi credentials");
#endif

    tcpip_adapter_init();
    VS_LOG_INFO("INIT: Begin WiFi initialization");
    INIT_STATUS_CHECK(esp_event_loop_init(event_handler, NULL), "Error register event task");
    ret_res = esp_wifi_init(&cfg);
    INIT_STATUS_CHECK(ret_res, "Error WiFi initialization [%d]", ret_res);
    INIT_STATUS_CHECK(ret_res = esp_wifi_set_mode(WIFI_MODE_STA), "Error set Wifi mode");
    INIT_STATUS_CHECK(ret_res = esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config), "Error set Wifi configuration");
    INIT_STATUS_CHECK(ret_res = esp_wifi_start(), "Error Wifi start");

    VS_LOG_INFO("connect to ap SSID:%s", wifi_config.sta.ssid);
    VS_LOG_INFO("INIT: End WiFi initialization");

terminate:
    return ret_res;
}

//******************************************************************************
esp_err_t
wifi_ready_wait(TickType_t xTicksToWait) {
    return xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, false, true, xTicksToWait);
}

//******************************************************************************
esp_err_t
wifi_get_mac(uint8_t *mac) {
    return esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
}

//******************************************************************************
static esp_err_t
_wifi_creds_load(uint8_t ssid[SSID_SZ], uint8_t pass[PASS_SZ]) {
    size_t len;
    esp_err_t ret_res = ESP_FAIL;
    uint32_t _handle;

    ret_res = nvs_open(NVS_WIFI, NVS_READONLY, &_handle);
    if (ret_res) {
        VS_LOG_ERROR("nvs_open failed");
        goto terminate;
    }

    len = SSID_SZ;
    ret_res = nvs_get_str(_handle, SSID_KEY, (char *)ssid, &len);
    if (ret_res) {
        VS_LOG_ERROR("nvs_get_str <SSID> failed");
        goto terminate;
    }

    len = PASS_SZ;
    ret_res = nvs_get_str(_handle, PASS_KEY, (char *)pass, &len);
    if (ret_res) {
        VS_LOG_ERROR("nvs_get_str <PASS> failed");
        goto terminate;
    }

    ret_res = ESP_OK;

terminate:
    nvs_close(_handle);

    return ret_res;
}

//******************************************************************************
esp_err_t
wifi_creds_save(const char *ssid, const char *pass) {
    esp_err_t ret_res = ESP_FAIL;
    uint32_t _handle;

    ret_res = nvs_open(NVS_WIFI, NVS_READWRITE, &_handle);
    if (ret_res) {
        VS_LOG_ERROR("nvs_open failed");
        goto terminate;
    }

    ret_res = nvs_set_str(_handle, SSID_KEY, ssid);
    if (ret_res) {
        VS_LOG_ERROR("nvs_set_str <SSID> failed");
        goto terminate;
    }

    ret_res = nvs_set_str(_handle, PASS_KEY, pass);
    if (ret_res) {
        VS_LOG_ERROR("nvs_set_str <PASS> failed");
        goto terminate;
    }

    ret_res = nvs_commit(_handle);
    if (ret_res) {
        VS_LOG_ERROR("nvs_commit fail");
        goto terminate;
    }

    ret_res = ESP_OK;

terminate:
    nvs_close(_handle);

    return ret_res;
}

//******************************************************************************
