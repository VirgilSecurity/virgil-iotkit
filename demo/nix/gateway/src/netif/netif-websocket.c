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

#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/cloud/base64.h>
#include <virgil/iot/json/json_parser.h>
#include <virgil/iot/json/json_generator.h>
#include "netif/curl-websocket.h"
#include <mbedtls/sha1.h>


static vs_status_e
_websock_init(struct vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb);

static vs_status_e
_websock_deinit(struct vs_netif_t *netif);

static vs_status_e
_websock_tx(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);

static vs_status_e
_websock_mac(const struct vs_netif_t *netif, struct vs_mac_addr_t *mac_addr);

static vs_netif_t _netif_websock = {.user_data = NULL,
                                    .init = _websock_init,
                                    .deinit = _websock_deinit,
                                    .tx = _websock_tx,
                                    .mac_addr = _websock_mac,
                                    .packet_buf_filled = 0};

static pthread_t main_loop_thread;
static vs_netif_rx_cb_t _websock_rx_cb = 0;
static vs_netif_process_cb_t _websock_process_cb = 0;
static char *_url = NULL;
static char *_account = NULL;
static const vs_secmodule_impl_t *_secmodule_impl;

static void
on_connect(void *data, CURL *easy, const char *websocket_protocols);
static void
on_text(void *data, CURL *easy, const char *text, size_t len);
static void
on_binary(void *data, CURL *easy, const void *mem, size_t len);
static void
on_ping(void *data, CURL *easy, const char *reason, size_t len);
static void
on_pong(void *data, CURL *easy, const char *reason, size_t len);
static void
on_close(void *data, CURL *easy, enum cws_close_reason reason, const char *reason_text, size_t reason_text_len);

static void
_calc_sha1(const void *input, const size_t input_len, void *output);
static void
_encode_base64(const uint8_t *input, const size_t input_len, char *output, size_t buf_sz);
static void
_get_random(void *buffer, size_t len);

// static pthread_t receive_thread;
static uint8_t _sim_mac_addr[6] = {2, 2, 2, 2, 2, 2};

#define RX_BUF_SZ (2048)

struct websocket_ctx {
    CURL *easy;
    CURLM *multi;
    int text_lines;
    int binary_lines;
    int exitval;
    bool running;
};

struct websocket_ctx _websocket_ctx = {
        .text_lines = 0,
        .binary_lines = 0,
        .exitval = EXIT_SUCCESS,
};

struct cws_callbacks cbs = {
        .on_connect = on_connect,
        .on_text = on_text,
        .on_binary = on_binary,
        .on_ping = on_ping,
        .on_pong = on_pong,
        .on_close = on_close,
        .calc_sha1 = _calc_sha1,
        .encode_base64 = _encode_base64,
        .get_random = _get_random,
        .data = &_websocket_ctx,
};

#define VS_WB_PAYLOAD_FILEND "payload"
#define VS_WB_ACCOUNT_ID_FILEND "account_id"

/******************************************************************************/
static void
_calc_sha1(const void *input, const size_t input_len, void *output) {
    VS_IOT_ASSERT(input);
    VS_IOT_ASSERT(output);
    VS_IOT_ASSERT(input_len);
    mbedtls_sha1_context ctx;

    mbedtls_sha1_init(&ctx);
    mbedtls_sha1(input, input_len, output);

    mbedtls_sha1_free(&ctx);
}

/******************************************************************************/
static void
_encode_base64(const uint8_t *input, const size_t input_len, char *output, size_t buf_sz) {
    int out_len = base64encode_len(input_len);

    VS_IOT_ASSERT(input);
    VS_IOT_ASSERT(input_len);
    VS_IOT_ASSERT(buf_sz < INT_MAX && buf_sz >= (size_t)out_len);

    char enc[out_len];
    VS_IOT_ASSERT(base64encode(input, input_len, enc, &out_len));
    memcpy(output, enc, out_len - 1);
}

/******************************************************************************/
static void
_get_random(void *buffer, size_t len) {
    VS_IOT_ASSERT(buffer);
    VS_IOT_ASSERT(len);
    VS_IOT_ASSERT(VS_CODE_OK == _secmodule_impl->random(buffer, len));
}

/******************************************************************************/
static void
on_connect(void *data, CURL *easy, const char *websocket_protocols) {
    VS_LOG_DEBUG("INFO: connected, websocket_protocols='%s'", websocket_protocols);
    _netif_websock.tx(&_netif_websock, (uint8_t *)"Hello", strlen("Hello"));
}

/******************************************************************************/
static void
_process_recv_data(const uint8_t *received_data, size_t recv_sz) {
    const uint8_t *packet_data = NULL;
    uint16_t packet_data_sz = 0;
    char *message = NULL;
    jobj_t jobj;
    int len;
    char *tmp = NULL;
    int decode_len;

    if (VS_JSON_ERR_OK != json_parse_start(&jobj, (char *)received_data, recv_sz)) {
        VS_LOG_ERROR("[WS]_process_recv_data. Unable to parse incoming message");
        return;
    }

    if (VS_JSON_ERR_OK != json_get_val_str_len(&jobj, VS_WB_PAYLOAD_FILEND, &len) || len < 0) {
        VS_LOG_ERROR("[WS] _process_recv_data answer not contain [payload] filed");
        return;
    }

    ++len;
    tmp = (char *)VS_IOT_MALLOC((size_t)len);
    if (NULL == tmp) {
        VS_LOG_ERROR("[WS] Can't allocate memory");
        return;
    }

    json_get_val_str(&jobj, VS_WB_PAYLOAD_FILEND, tmp, len);

    decode_len = base64decode_len(tmp, len);

    if (0 >= decode_len) {
        VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) wrong size [ca_certificate]");
        goto terminate;
    }

    message = (char *)VS_IOT_MALLOC((size_t)decode_len);
    if (NULL == message) {
        VS_LOG_ERROR("[MB] Can't allocate memory");
        goto terminate;
    }

    base64decode(tmp, len, (uint8_t *)message, &decode_len);

    // Pass received data to upper level via callback
    if (_websock_rx_cb) {
        if (0 == _websock_rx_cb(&_netif_websock, (uint8_t *)message, decode_len, &packet_data, &packet_data_sz)) {
            // Ready to process packet
            if (_websock_process_cb) {
                _websock_process_cb(&_netif_websock, packet_data, packet_data_sz);
            }
        }
    }
terminate:
    free(tmp);
    free(message);
}

/******************************************************************************/
static void
on_text(void *data, CURL *easy, const char *text, size_t len) {
    VS_LOG_DEBUG("INFO: TEXT={\n%s\n}", text);
    _process_recv_data((uint8_t *)text, len);
    (void)len;
}

/******************************************************************************/
static void
on_binary(void *data, CURL *easy, const void *mem, size_t len) {

    const uint8_t *bytes = mem;

    VS_LOG_DEBUG("[WS] INFO: BINARY=%zd bytes", len);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "[WS] {}", bytes, len);
    _process_recv_data(mem, len);
    cws_ping(easy, "ping", SIZE_MAX);
}

/******************************************************************************/
static void
on_ping(void *data, CURL *easy, const char *reason, size_t len) {
    VS_LOG_DEBUG("[WS] INFO: PING %zd bytes='%s'", len, reason);
    cws_pong(easy, reason, len);
    (void)data;
}

/******************************************************************************/
static void
on_pong(void *data, CURL *easy, const char *reason, size_t len) {
    VS_LOG_DEBUG("[WS] INFO: PONG %zd bytes='%s'", len, reason);
    (void)data;
}

/******************************************************************************/
static void
on_close(void *data, CURL *easy, enum cws_close_reason reason, const char *reason_text, size_t reason_text_len) {
    struct websocket_ctx *ctx = data;
    VS_LOG_DEBUG("[WS] INFO: CLOSE=%4d %zd bytes '%s'", reason, reason_text_len, reason_text);

    ctx->exitval = (reason == CWS_CLOSE_REASON_NORMAL ? EXIT_SUCCESS : EXIT_FAILURE);
    ctx->running = false;
    (void)easy;
}

/******************************************************************************/
static void *
_websocket_main_loop_processor(void *sock_desc) {
    int still_running;
    vs_log_thread_descriptor("websock");
    do {
        // websocket cycle
        CURLMcode mc; /* curl_multi_poll() return code */
        int numfds;

        /* we start some action by calling perform right away */
        mc = curl_multi_perform(_websocket_ctx.multi, &still_running);

        if (CURLM_OK == mc) {
            /* wait for activity, timeout or "nothing" */
            mc = curl_multi_wait(_websocket_ctx.multi, NULL, 0, 20000, &numfds);
            if (mc != CURLM_OK) {
                VS_LOG_ERROR("curl_multi_wait() failed, code %d.\n", mc);
                break;
            }
        } else {
            VS_LOG_ERROR("curl_multi_perform() failed, code %d.\n", mc);
        }

    } while (_websocket_ctx.running && still_running);

    return NULL;
}

/******************************************************************************/
static vs_status_e
_websock_connect() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    _websocket_ctx.easy = cws_new(_url, NULL, &cbs);
    if (!_websocket_ctx.easy) {
        goto error_easy;
    }

    /* here you should do any extra sets, like cookies, auth... */
    curl_easy_setopt(_websocket_ctx.easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(_websocket_ctx.easy, CURLOPT_VERBOSE, 1L);

    _websocket_ctx.multi = curl_multi_init();
    if (!_websocket_ctx.multi) {
        goto error_multi;
    }

    curl_multi_add_handle(_websocket_ctx.multi, _websocket_ctx.easy);

    _websocket_ctx.running = true;

    // Start receive thread
    if (0 == pthread_create(&main_loop_thread, NULL, _websocket_main_loop_processor, NULL)) {
        return VS_CODE_OK;
    }

    VS_LOG_ERROR("Can't start websocket thread");

error_multi:
    cws_free(_websocket_ctx.easy);
error_easy:
    curl_global_cleanup();
    _websocket_ctx.running = false;

    _websock_deinit(&_netif_websock);

    return VS_CODE_ERR_SOCKET;
}

/******************************************************************************/
static bool
_make_message(char **message, const uint8_t *data, size_t data_sz, bool is_stat) {

    *message = 0;
    CHECK_NOT_ZERO_RET(message, false);
    CHECK_NOT_ZERO_RET(_account, false);

    char *frame;
    size_t frame_size = base64encode_len(data_sz) + strlen(_account) + 48;

    frame = (char *)malloc(frame_size);
    VS_IOT_ASSERT(frame != 0);

    struct json_str json;
    json_str_init(&json, frame, frame_size);
    json_start_object(&json);

    json_set_val_str(&json, VS_WB_ACCOUNT_ID_FILEND, _account);

    json_set_val_int(&json, "s", is_stat ? 1 : 0);

    int base64_sz = base64encode_len(data_sz);
    char *data_b64 = (char *)malloc(base64_sz);
    base64encode((const unsigned char *)data, data_sz, data_b64, &base64_sz);
    json_set_val_str(&json, VS_WB_PAYLOAD_FILEND, data_b64);
    free(data_b64);
    json_close_object(&json);

    *message = (char *)json.buff;
    return true;
}

/******************************************************************************/
static vs_status_e
_websock_tx(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    (void)netif;
    vs_status_e ret;
    char *msg = NULL;
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(_make_message(&msg, data, data_sz, false), VS_CODE_ERR_TX_SNAP, "Unable to create websocket frame");
    CHECK_NOT_ZERO_RET(msg, VS_CODE_ERR_TX_SNAP);

    VS_LOG_DEBUG("[WS] send message = %s", msg);
    ret = cws_send_text(_websocket_ctx.easy, msg) ? VS_CODE_OK : VS_CODE_ERR_SOCKET;
    free(msg);
    return ret;
}

/******************************************************************************/
static vs_status_e
_websock_init(struct vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb) {
    (void)netif;

    VS_IOT_ASSERT(rx_cb);
    CHECK_NOT_ZERO_RET(rx_cb, VS_CODE_ERR_NULLPTR_ARGUMENT);

    _websock_rx_cb = rx_cb;
    _websock_process_cb = process_cb;
    _netif_websock.packet_buf_filled = 0;

    return _websock_connect();
}

/******************************************************************************/
static vs_status_e
_websock_deinit(struct vs_netif_t *netif) {
    (void)netif;

    if (_websocket_ctx.running) {
        _websocket_ctx.running = false;
        pthread_join(main_loop_thread, NULL);

        cws_close(_websocket_ctx.easy, CWS_CLOSE_REASON_NORMAL, "close it!", SIZE_MAX);

        curl_multi_remove_handle(_websocket_ctx.multi, _websocket_ctx.easy);
        curl_multi_cleanup(_websocket_ctx.multi);
        cws_free(_websocket_ctx.easy);
        curl_global_cleanup();
    }

    free(_url);
    _url = NULL;
    free(_account);
    _account = NULL;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_websock_mac(const struct vs_netif_t *netif, struct vs_mac_addr_t *mac_addr) {
    (void)netif;

    if (mac_addr) {
        memcpy(mac_addr->bytes, _sim_mac_addr, sizeof(vs_mac_addr_t));
        return VS_CODE_OK;
    }

    return VS_CODE_ERR_NULLPTR_ARGUMENT;
}

/******************************************************************************/
vs_netif_t *
vs_hal_netif_websock(const char *url,
                     const char *account,
                     vs_secmodule_impl_t *secmodule_impl,
                     vs_mac_addr_t mac_addr) {

    VS_IOT_ASSERT(url);
    VS_IOT_ASSERT(account);
    VS_IOT_ASSERT(secmodule_impl);

    CHECK_NOT_ZERO_RET(url, NULL);
    CHECK_NOT_ZERO_RET(account, NULL);
    CHECK_NOT_ZERO_RET(secmodule_impl, NULL);

    _websock_deinit(&_netif_websock);

    memcpy(_sim_mac_addr, mac_addr.bytes, sizeof(vs_mac_addr_t));

    _secmodule_impl = secmodule_impl;
    _url = strdup(url);
    _account = strdup(account);

    if (NULL == _url || NULL == account) {
        _websock_deinit(&_netif_websock);
        VS_LOG_ERROR("Can't allocate memory for websocket creds");
        return NULL;
    }

    return &_netif_websock;
}
/******************************************************************************/