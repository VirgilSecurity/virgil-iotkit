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

#include <virgil/iot/cloud/cloud.h>
#include <string.h>
#include <curl/curl.h>

typedef struct resp_buff_s {
    uint8_t *buff;
    size_t buff_sz;
    size_t used_size;
    vs_fetch_handler_cb_t fetch_handler;
    void *userdata;
} resp_buff_t;

static vs_status_e
_curl_http_hal(vs_cloud_http_method_e method,
               const char *url,
               const char *request_body,
               size_t request_body_size,
               char *out_data,
               vs_fetch_handler_cb_t fetch_handler,
               void *hander_data,
               size_t *in_out_size);

static const vs_cloud_impl_t _impl = {
        .http_request = _curl_http_hal,
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
static vs_status_e
_curl_http_hal(vs_cloud_http_method_e method,
               const char *url,
               const char *request_body,
               size_t request_body_size,
               char *out_data,
               vs_fetch_handler_cb_t fetch_handler,
               void *fetch_hander_data,
               size_t *in_out_size) {
    CURL *curl;
    CURLcode curl_res;
    vs_status_e res = VS_CODE_OK;

    if (NULL == in_out_size) {
        return VS_CODE_ERR_REQUEST_PREPARE;
    }

    resp_buff_t resp = {(uint8_t *)out_data, *in_out_size, 0, fetch_handler, fetch_hander_data};

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

        switch (method) {
        case VS_CLOUD_REQUEST_GET:
            curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
            break;
        case VS_CLOUD_REQUEST_POST:
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_body_size);
            break;
        default:
            res = VS_CODE_ERR_INCORRECT_PARAMETER;
            curl_easy_cleanup(curl);
            goto terminate;
        }

        curl_res = curl_easy_perform(curl);

        if (CURLE_OK != curl_res) {
            res = VS_CODE_ERR_REQUEST_SEND;
        }
        *in_out_size = resp.used_size;
        curl_easy_cleanup(curl);
    }

terminate:

    return res;
}

/******************************************************************************/
const vs_cloud_impl_t *
vs_curl_http_impl(void) {
    return &_impl;
}
