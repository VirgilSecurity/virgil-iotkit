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


static EventGroupHandle_t s_wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;
static int s_retry_num = 0;

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
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED: {
        if (s_retry_num < ESP_WIFI_MAXIMUM_RETRY) {
            esp_wifi_connect();
            xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
            s_retry_num++;
            VS_LOG_INFO("retry to connect to the AP");
        }
        VS_LOG_INFO("connect to the AP fail\n");
        break;
    }
    default:
        break;
    }
    return ESP_OK;
}

//******************************************************************************
esp_err_t
wifi_init_sta(wifi_config_t wifi_config) {
    esp_err_t ret_res = ESP_FAIL;
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    s_wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    VS_LOG_INFO("INIT: Begin WiFi initialization");
    INIT_STATUS_CHECK(esp_event_loop_init(event_handler, NULL), "Error register event task");
    INIT_STATUS_CHECK(ret_res = esp_wifi_init(&cfg), "Error WiFi initialization [%d]", ret_res);
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
