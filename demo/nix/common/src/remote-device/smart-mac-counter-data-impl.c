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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <virgil/iot/logger/logger.h>
#include "helpers/msg-queue.h"

#include <smart-mac-counter-data-impl.h>
#include <virgil/iot/vs-curl-http/curl-http.h>

#define REMOTE_URL_STR_SIZE (200)

static pthread_t counter_thread;
static pthread_mutex_t _get_data_mtx;

#define SMART_MAC_COUNTER_POLL_PERIOD_MS (5000)

#define RESPONSE_SZ_MAX (1024)

#define GET_DATA_REQ_PREFIX "?page=getdata&devid="
#define GET_DATA_REQ_DEVPASS "&devpass="

static char *_url = NULL;
static bool is_thread_started = false;

static char get_buf[RESPONSE_SZ_MAX];
static uint32_t get_data_sz;
static bool is_remote_dev_ready;

/*************************************************************************/
static void *
_counter_exch_data_task(void *pvParameters) {
    const vs_cloud_impl_t *curl_impl = vs_curl_http_impl();
    char tmp[RESPONSE_SZ_MAX];
    size_t result_size = sizeof(tmp);

    assert(curl_impl);
    if (NULL == curl_impl) {
        VS_LOG_ERROR("Incorrect cloud curl impl");
        exit(-1);
    }
    assert(curl_impl->http_request);
    if (NULL == curl_impl->http_request) {
        VS_LOG_ERROR("Incorrect cloud curl http_request impl");
        exit(-1);
    }

    while (1) {
        vs_impl_msleep(SMART_MAC_COUNTER_POLL_PERIOD_MS);
        if (VS_CODE_OK == curl_impl->http_request(VS_CLOUD_REQUEST_GET, _url, NULL, 0, tmp, NULL, NULL, &result_size)) {
            if (0 == pthread_mutex_lock(&_get_data_mtx)) {
                memcpy(get_buf, tmp, result_size);
                is_remote_dev_ready = true;
                get_data_sz = result_size;
            }
        } else {
            if (0 == pthread_mutex_lock(&_get_data_mtx)) {
                get_data_sz = 0;
                is_remote_dev_ready = false;
            }
        }

        (void)pthread_mutex_unlock(&_get_data_mtx);
    }

    return NULL;
}

/******************************************************************************/
vs_status_e
vs_smart_mac_counter_get_data(uint8_t *data, uint32_t buf_sz, uint32_t *data_sz) {
    vs_status_e ret = VS_CODE_ERR_FILE_READ;
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *data_sz = 0;

    if (!is_thread_started) {
        return VS_CODE_ERR_NOINIT;
    }

    if (0 == pthread_mutex_lock(&_get_data_mtx)) {
        CHECK(get_data_sz <= buf_sz, "Input buffer is too small");
        CHECK(is_remote_dev_ready, "Remote device is not respond");
        memcpy(data, get_buf, get_data_sz);
        *data_sz = get_data_sz;
    }
    ret = VS_CODE_OK;

terminate:
    (void)pthread_mutex_unlock(&_get_data_mtx);
    return ret;
}

/******************************************************************************/
vs_status_e
vs_smart_mac_counter_set_data(uint8_t *data, uint32_t data_sz) {
    if (!is_thread_started) {
        return VS_CODE_ERR_NOINIT;
    }
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_init_smart_mac_counter(const char *url,
                          size_t url_len,
                          const char *id,
                          size_t id_len,
                          const char *pass,
                          size_t pass_len) {
    if (is_thread_started) {
        return VS_CODE_ERR_THREAD;
    }

    CHECK_NOT_ZERO_RET(url, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(pass, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(url_len <= SMART_MAC_COUNTER_HOST_MAX_STR_SZ, VS_CODE_ERR_INCORRECT_ARGUMENT, "url is too big");
    CHECK_RET(id_len <= SMART_MAC_COUNTER_ID_MAX_STR_SZ, VS_CODE_ERR_INCORRECT_ARGUMENT, "id is too big");
    CHECK_RET(pass_len <= SMART_MAC_COUNTER_PASS_MAX_STR_SZ, VS_CODE_ERR_INCORRECT_ARGUMENT, "pass is too big");
    CHECK_RET(url[url_len - 1] == 0, VS_CODE_ERR_INCORRECT_ARGUMENT, "url is not a null terminated string");
    CHECK_RET(id[id_len - 1] == 0, VS_CODE_ERR_INCORRECT_ARGUMENT, "id is not a null terminated string");
    CHECK_RET(pass[pass_len - 1] == 0, VS_CODE_ERR_INCORRECT_ARGUMENT, "pass is not a null terminated string");

    get_data_sz = 0;
    is_remote_dev_ready = false;
    size_t url_sz =
            strlen(url) + strlen(GET_DATA_REQ_PREFIX) + strlen(id) + strlen(GET_DATA_REQ_DEVPASS) + strlen(pass) + 1;
    _url = malloc(url_sz);
    CHECK(NULL != _url, "[SMART_MAC] Can't allocate memory");
    int res = snprintf(_url, url_sz, "%s%s%s%s%s", url, GET_DATA_REQ_PREFIX, id, GET_DATA_REQ_DEVPASS, pass);
    CHECK(res > 0 && res <= url_sz, "Error create url");


    CHECK(0 == pthread_mutex_init(&_get_data_mtx, NULL), "Error init mutex var %s (%d)", strerror(errno), errno);

    is_thread_started = (0 == pthread_create(&counter_thread, NULL, _counter_exch_data_task, NULL));
    if (!is_thread_started) {
        pthread_mutex_destroy(&_get_data_mtx);
        return VS_CODE_ERR_NOINIT;
    }

    return VS_CODE_OK;

terminate:
    free(_url);
    _url = NULL;

    return VS_CODE_ERR_NOINIT;
}

/******************************************************************************/
vs_status_e
vs_deinit_smart_mac_counter(void) {
    vs_status_e ret = VS_CODE_OK;

    if (is_thread_started) {
        void *res;

        if (0 != pthread_cancel(counter_thread) || 0 != pthread_join(counter_thread, &res) || PTHREAD_CANCELED != res) {
            VS_LOG_ERROR("Unable to cancel counter_thread");
            ret = VS_CODE_ERR_THREAD;
        }

        pthread_mutex_destroy(&_get_data_mtx);
        free(_url);
        _url = NULL;
        is_thread_started = false;
    }
    return VS_CODE_OK;
}

/******************************************************************************/
