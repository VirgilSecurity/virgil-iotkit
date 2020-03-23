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

#include "esp_system.h"
#include "esp_http_client.h"

#include <virgil/iot/cloud/cloud.h>
#include <string.h>

typedef struct resp_buff_s {
    uint8_t *buff;
    size_t buff_sz;
    size_t used_size;
    vs_fetch_handler_cb_t fetch_handler;
    void *userdata;
} resp_buff_t;

static vs_status_e
_esp_http_hal(vs_cloud_http_method_e method,
              const char *url,
              const char *request_body,
              size_t request_body_size,
              char *out_data,
              vs_fetch_handler_cb_t fetch_handler,
              void *hander_data,
              size_t *in_out_size);

static const vs_cloud_impl_t _impl = {
        .http_request = _esp_http_hal,
};

/******************************************************************************/
static size_t
_write_callback(char *contents, size_t size, size_t nmemb, void *userdata) {
    resp_buff_t *resp = (resp_buff_t *)userdata;
    size_t chunksize = size * nmemb;

    if (resp->fetch_handler) {
        return resp->fetch_handler(contents, chunksize, resp->userdata);
    }

    if (NULL == resp->buff || resp->used_size + chunksize > resp->buff_sz) {
        return 0;
    }
    memcpy(&(resp->buff[resp->used_size]), contents, chunksize);
    resp->used_size += chunksize;
    return chunksize;
}

/******************************************************************************/
esp_err_t
_http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
        VS_LOG_ERROR("HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        VS_LOG_DEBUG("HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        VS_LOG_DEBUG("HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        VS_LOG_DEBUG("HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        VS_LOG_DEBUG("HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        _write_callback((char *)evt->data, evt->data_len, 1, evt->user_data);
        break;
    case HTTP_EVENT_ON_FINISH:
        VS_LOG_DEBUG("HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        VS_LOG_DEBUG("HTTP_EVENT_DISCONNECTED");
        break;
    }
    return ESP_OK;
}

/******************************************************************************/
static vs_status_e
_esp_http_hal(vs_cloud_http_method_e method,
              const char *url,
              const char *request_body,
              size_t request_body_size,
              char *out_data,
              vs_fetch_handler_cb_t fetch_handler,
              void *fetch_hander_data,
              size_t *in_out_size) {

    vs_status_e res = VS_CODE_OK;
    esp_err_t err;
    esp_http_client_config_t config;
    memset(&config, 0, sizeof(esp_http_client_config_t));
    config.url = url;
    config.event_handler = _http_event_handler;
    config.transport_type = HTTP_TRANSPORT_OVER_SSL;
    config.timeout_ms = 5000;

    CHECK_NOT_ZERO_RET(in_out_size, VS_CODE_ERR_REQUEST_PREPARE);

    resp_buff_t resp = {.buff = (uint8_t *)out_data,
                        .buff_sz = *in_out_size,
                        .used_size = 0,
                        .fetch_handler = fetch_handler,
                        .userdata = fetch_hander_data};

    config.user_data = (void *)&resp;

    esp_http_client_handle_t client = esp_http_client_init(&config);

    if (client) {
        switch (method) {
        case VS_CLOUD_REQUEST_GET:
            esp_http_client_set_method(client, HTTP_METHOD_GET);
            break;
        case VS_CLOUD_REQUEST_POST:
            esp_http_client_set_method(client, HTTP_METHOD_POST);
            esp_http_client_set_post_field(client, request_body, request_body_size);
            break;
        default:
            res = VS_CODE_ERR_INCORRECT_PARAMETER;
            esp_http_client_cleanup(client);
            goto terminate;
        }

        err = esp_http_client_perform(client);

        if (ESP_OK != err) {
            VS_LOG_ERROR("Error perform http request %s", esp_err_to_name(err));
            res = VS_CODE_ERR_REQUEST_SEND;
        }
        *in_out_size = resp.used_size;
        esp_http_client_cleanup(client);
    }

terminate:

    return res;
}

/******************************************************************************/
const vs_cloud_impl_t *
vs_esp_http_impl(void) {
    return &_impl;
}
