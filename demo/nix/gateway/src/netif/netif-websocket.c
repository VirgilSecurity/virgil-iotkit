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
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/cloud/base64.h>
#include <virgil/iot/json/json_parser.h>
#include <virgil/iot/json/json_generator.h>
#include "netif/curl-websocket.h"
#include <mbedtls/sha1.h>

#include <helpers/event-group-bits.h>
#include <helpers/msg-queue.h>

#define WS_QUEUE_SZ (100)
static vs_msg_queue_ctx_t *_queue_ctx = 0;

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

static pthread_t socket_pool_thread;
static pthread_t curl_perform_loop_thread;

static vs_netif_rx_cb_t _websock_rx_cb = 0;
static vs_netif_process_cb_t _websock_process_cb = 0;
static char *_url = NULL;
static char *_account = NULL;
static const vs_secmodule_impl_t *_secmodule_impl;

static void
_cws_on_connect_cb(void *data, CURL *easy, const char *websocket_protocols);
static void
_cws_on_text_rcv_cb(void *data, CURL *easy, const char *text, size_t len);
static void
_cws_on_binary_rcv_cb(void *data, CURL *easy, const void *mem, size_t len);
static void
_cws_on_ping_rcv_cb(void *data, CURL *easy, const char *reason, size_t len);
static void
_cws_on_pong_rcv_cb(void *data, CURL *easy, const char *reason, size_t len);
static void
_cws_on_close_cb(void *data, CURL *easy, enum cws_close_reason reason, const char *reason_text, size_t reason_text_len);

static void
_cws_calc_sha1(const void *input, size_t input_len, void *output);
static void
_cws_encode_base64(const uint8_t *input, size_t input_len, char *output, size_t buf_sz);
static int
_cws_get_random(void *buffer, size_t len);


static void *
_websocket_curl_perform_loop_processor(void *param);
static void *
_websocket_pool_socket_processor(void *param);
static vs_status_e
_websocket_connect(void);
static vs_status_e
_websocket_reconnect(vs_event_bits_t stat);


static bool
_make_message(char **message, const uint8_t *data, size_t data_sz, bool is_stat);

// static pthread_t receive_thread;
static uint8_t _sim_mac_addr[6] = {2, 2, 2, 2, 2, 2};

#define RX_BUF_SZ (2048)

struct websocket_ctx {
    bool is_initialized;
    CURL *easy;
    CURLM *multi;
    struct sockaddr_in servaddr;
    curl_socket_t sockfd;
    int exitval;
    vs_event_group_bits_t ws_events;
};

struct websocket_ctx _websocket_ctx = {
        .exitval = EXIT_SUCCESS,
};

struct cws_callbacks cbs = {
        .on_connect = _cws_on_connect_cb,
        .on_text = _cws_on_text_rcv_cb,
        .on_binary = _cws_on_binary_rcv_cb,
        .on_ping = _cws_on_ping_rcv_cb,
        .on_pong = _cws_on_pong_rcv_cb,
        .on_close = _cws_on_close_cb,
        .calc_sha1 = _cws_calc_sha1,
        .encode_base64 = _cws_encode_base64,
        .get_random = _cws_get_random,
        .data = &_websocket_ctx,
};

// thread safe event flags
#define WS_EVF_STOP_ALL_THREADS EVENT_BIT(0)
#define WS_EVF_STOP_PERFORM_THREAD EVENT_BIT(1)
#define WS_EVF_SOCKET_CONNECTED EVENT_BIT(2)
#define WS_EVF_PERFORM_THREAD_EXIT EVENT_BIT(3)
#define WS_EVF_WS_CONNECTED EVENT_BIT(4)

#define VS_WB_PAYLOAD_FIELD "payload"
#define VS_WB_ACCOUNT_ID_FIELD "account_id"
#define VS_WB_SUBSCR_MESSAGE "\x30\x81\xA1"
/******************************************************************************/
static void
_cws_calc_sha1(const void *input, size_t input_len, void *output) {
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
_cws_encode_base64(const uint8_t *input, size_t input_len, char *output, size_t buf_sz) {
    int out_len = base64encode_len(input_len);

    VS_IOT_ASSERT(input);
    VS_IOT_ASSERT(input_len);
    VS_IOT_ASSERT(buf_sz < INT_MAX && buf_sz >= (size_t)(out_len - 1));

    char enc[out_len];
    memset(enc, 0, out_len);

    if (!base64encode(input, input_len, enc, &out_len)) {
        VS_IOT_ASSERT(false);
    }

    memcpy(output, enc, out_len - 1);
}

/******************************************************************************/
static int
_cws_get_random(void *buffer, size_t len) {
    vs_status_e ret;
    VS_IOT_ASSERT(buffer);
    VS_IOT_ASSERT(len);
    ret = _secmodule_impl->random(buffer, len);
    VS_IOT_ASSERT(VS_CODE_OK == ret);

    return (VS_CODE_OK == ret) ? 0 : -1;
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
        VS_LOG_ERROR("Unable to parse incoming message");
        return;
    }

    CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_WB_PAYLOAD_FIELD, &len) && len > 0,
          "Message does not contain [payload] filed");

    ++len;
    tmp = (char *)malloc((size_t)len);
    VS_IOT_ASSERT(tmp);
    CHECK(tmp != NULL, "Can't allocate memory");

    json_get_val_str(&jobj, VS_WB_PAYLOAD_FIELD, tmp, len);

    decode_len = base64decode_len(tmp, len);
    CHECK(0 < decode_len, "Wrong payload size");

    message = (char *)malloc((size_t)decode_len);
    VS_IOT_ASSERT(message);
    CHECK(message != NULL, "Can't allocate memory");

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
    json_parse_stop(&jobj);
    free(tmp);
    free(message);
}

/******************************************************************************/
static void
_cws_on_connect_cb(void *data, CURL *easy, const char *websocket_protocols) {
    (void)data;
    (void)easy;
    VS_LOG_DEBUG("INFO: connected, websocket_protocols='%s'", websocket_protocols);
    vs_event_group_set_bits(&_websocket_ctx.ws_events, WS_EVF_WS_CONNECTED);
}

/******************************************************************************/
static void
_cws_on_text_rcv_cb(void *data, CURL *easy, const char *text, size_t len) {
    (void)data;
    (void)easy;
    VS_LOG_DEBUG("INFO: TEXT={\n%s\n}", text);

    _process_recv_data((uint8_t *)text, len);
}

/******************************************************************************/
static void
_cws_on_binary_rcv_cb(void *data, CURL *easy, const void *mem, size_t len) {
    (void)data;
    (void)easy;
    const uint8_t *bytes = mem;

    VS_LOG_DEBUG("INFO: BINARY=%zd bytes", len);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "[WS] ", bytes, len);
    _process_recv_data(mem, len);
}

/******************************************************************************/
static void
_cws_on_ping_rcv_cb(void *data, CURL *easy, const char *reason, size_t len) {
    (void)data;
    (void)easy;
    //    VS_LOG_DEBUG("INFO: PING %zd bytes='%s'", len, reason);
    cws_pong(easy, reason, len);
}

/******************************************************************************/
static void
_cws_on_pong_rcv_cb(void *data, CURL *easy, const char *reason, size_t len) {
    (void)data;
    (void)easy;
    (void)reason;
    (void)len;
    //    VS_LOG_DEBUG("INFO: PONG %zd bytes='%s'", len, reason);
}

/******************************************************************************/
static void
_cws_on_close_cb(void *data,
                 CURL *easy,
                 enum cws_close_reason reason,
                 const char *reason_text,
                 size_t reason_text_len) {
    struct websocket_ctx *ctx = data;
    vs_event_group_clear_bits(&_websocket_ctx.ws_events, WS_EVF_SOCKET_CONNECTED | WS_EVF_WS_CONNECTED);
    close(ctx->sockfd);

    VS_LOG_DEBUG("[WS] INFO: CLOSE=%4d %zd bytes '%s'", reason, reason_text_len, reason_text);

    ctx->exitval = (reason == CWS_CLOSE_REASON_NORMAL ? EXIT_SUCCESS : EXIT_FAILURE);
    (void)easy;
}

/******************************************************************************/
static curl_socket_t
_curl_opensocket_cb(void *clientp, curlsocktype purpose, struct curl_sockaddr *address) {
    (void)purpose;
    (void)clientp;

    VS_LOG_DEBUG("Try to open socket");
    /* Create the socket "manually" */
    _websocket_ctx.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (_websocket_ctx.sockfd == CURL_SOCKET_BAD) {
        VS_LOG_ERROR("Error creating listening socket.");
        return CURL_SOCKET_BAD;
    }

    // Because sockaddr_in and sockadd structs can be mapped to each other
    memcpy(&_websocket_ctx.servaddr, &address->addr, sizeof(_websocket_ctx.servaddr));

    if (connect(_websocket_ctx.sockfd, (struct sockaddr *)&_websocket_ctx.servaddr, sizeof(_websocket_ctx.servaddr)) ==
        -1) {
        close(_websocket_ctx.sockfd);
        VS_LOG_ERROR("client error: connect: %s", strerror(errno));
        return CURL_SOCKET_BAD;
    }

    vs_event_group_set_bits(&_websocket_ctx.ws_events, WS_EVF_SOCKET_CONNECTED);

    return _websocket_ctx.sockfd;
}

/******************************************************************************/
static int
_curl_socketopt_cb(void *clientp, curl_socket_t curlfd, curlsocktype purpose) {
    (void)clientp;
    (void)curlfd;
    (void)purpose;
    /* This return code was added in libcurl 7.21.5 */
    return CURL_SOCKOPT_ALREADY_CONNECTED;
}

/******************************************************************************/
static CURL *
_cws_config(void) {
    CURL *easy = cws_new(_url, NULL, &cbs);
    if (!easy) {
        return NULL;
    }

    /* here you should do any extra sets, like cookies, auth... */
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
    //    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, _curl_opensocket_cb);
    curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA, &_websocket_ctx.sockfd);
    curl_easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, _curl_socketopt_cb);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL, 20L);
    return easy;
}

/******************************************************************************/
static void
_cws_cleanup_resources(void) {
    curl_multi_remove_handle(_websocket_ctx.multi, _websocket_ctx.easy);
    cws_free(_websocket_ctx.easy);

    if (vs_event_group_wait_bits(&_websocket_ctx.ws_events, WS_EVF_SOCKET_CONNECTED, false, false, 0)) {
        vs_event_group_clear_bits(&_websocket_ctx.ws_events, WS_EVF_SOCKET_CONNECTED | WS_EVF_WS_CONNECTED);
    }
}

/******************************************************************************/
static vs_status_e
_websocket_connect(void) {
    vs_event_bits_t stat;
    _websocket_ctx.easy = _cws_config();
    CHECK_RET(_websocket_ctx.easy, VS_CODE_ERR_INIT_SNAP, "Can't create curl easy ctx");

    _websocket_ctx.multi = curl_multi_init();
    if (!_websocket_ctx.multi) {
        VS_LOG_ERROR("Can't create curl easy ctx");
        cws_free(_websocket_ctx.easy);
        return VS_CODE_ERR_INIT_SNAP;
    }

    curl_multi_add_handle(_websocket_ctx.multi, _websocket_ctx.easy);

    while (1) {
        // Start receive thread
        CHECK(0 == pthread_create(&curl_perform_loop_thread, NULL, _websocket_curl_perform_loop_processor, NULL),
              "Can't start websocket main loop processor");
        VS_LOG_DEBUG("Perform thread has been started");

        stat = vs_event_group_wait_bits(&_websocket_ctx.ws_events,
                                        WS_EVF_SOCKET_CONNECTED | WS_EVF_STOP_ALL_THREADS | WS_EVF_PERFORM_THREAD_EXIT,
                                        false,
                                        false,
                                        20);

        // Stop interface
        if (stat & WS_EVF_STOP_ALL_THREADS) {
            return VS_CODE_ERR_DEINIT_SNAP;
        }

        // Socket has been connected successfully
        if (stat & WS_EVF_SOCKET_CONNECTED && !(stat & WS_EVF_PERFORM_THREAD_EXIT)) {
            return VS_CODE_OK;
        }


        vs_event_group_set_bits(&_websocket_ctx.ws_events, WS_EVF_STOP_PERFORM_THREAD);
        pthread_join(curl_perform_loop_thread, NULL);
        vs_event_group_clear_bits(&_websocket_ctx.ws_events, WS_EVF_PERFORM_THREAD_EXIT | WS_EVF_STOP_PERFORM_THREAD);
        VS_LOG_DEBUG("_websocket_connect. Preform thread has been stopped");

        // The connection attempt has been fail. Repeat
        _cws_cleanup_resources();
        _websocket_ctx.easy = _cws_config();
        CHECK_RET(_websocket_ctx.easy, VS_CODE_ERR_INIT_SNAP, "Can't create curl easy ctx");
        curl_multi_add_handle(_websocket_ctx.multi, _websocket_ctx.easy);
        sleep(5);
    }

terminate:
    _cws_cleanup_resources();
    curl_multi_cleanup(_websocket_ctx.multi);
    return VS_CODE_ERR_INIT_SNAP;
}

/******************************************************************************/
static vs_status_e
_websocket_reconnect(vs_event_bits_t stat) {
    if (!(stat & WS_EVF_PERFORM_THREAD_EXIT)) {
        vs_event_group_set_bits(&_websocket_ctx.ws_events, WS_EVF_STOP_PERFORM_THREAD);
        pthread_join(curl_perform_loop_thread, NULL);
        VS_LOG_DEBUG("_websocket_reconnect. Preform thread has been stopped");
    }

    _cws_cleanup_resources();
    curl_multi_cleanup(_websocket_ctx.multi);
    return _websocket_connect();
}

/******************************************************************************/
static void *
_websocket_curl_perform_loop_processor(void *param) {
    (void)param;
    int still_running;
    vs_log_thread_descriptor("ws perform");
    vs_event_bits_t stat;

    VS_LOG_DEBUG("Perform thread enter");
    do {
        // websocket cycle
        CURLMcode mc;
        int numfds;
        /* we start some action by calling perform right away */
        mc = curl_multi_perform(_websocket_ctx.multi, &still_running);

        if (CURLM_OK == mc && still_running) {
            /* wait for activity, timeout or "nothing" */
            mc = curl_multi_wait(_websocket_ctx.multi, NULL, 0, 1000, &numfds);

            if (mc != CURLM_OK) {
                VS_LOG_ERROR("curl_multi_wait() failed, code %d.", mc);
                still_running = 0;
            }
        } else if (!still_running) {
            VS_LOG_ERROR("curl_multi_perform(). still_running = false");
        } else {
            VS_LOG_ERROR("curl_multi_perform() failed, code %d.", mc);
            still_running = 0;
        }

        // Check if need to stop curl multi polling
        stat = vs_event_group_wait_bits(&_websocket_ctx.ws_events, WS_EVF_STOP_PERFORM_THREAD, true, false, 0);
    } while (!stat && still_running);

    curl_easy_pause(_websocket_ctx.easy, CURLPAUSE_ALL);
    VS_LOG_DEBUG("Perform thread exit");

    vs_event_group_set_bits(&_websocket_ctx.ws_events, WS_EVF_PERFORM_THREAD_EXIT);
    return NULL;
}

/******************************************************************************/
static vs_status_e
_message_queue_processing(bool *is_subscr_msg_sent) {
    vs_event_bits_t stat;
    vs_netif_t *netif = 0;
    const uint8_t *data = 0;
    size_t data_sz = 0;
    vs_status_e ret;

    VS_IOT_ASSERT(_queue_ctx);
    if (!_queue_ctx) {
        return VS_CODE_ERR_QUEUE;
    }

    stat = vs_event_group_wait_bits(&_websocket_ctx.ws_events, WS_EVF_WS_CONNECTED, false, false, 0);
    if (!stat) {
        *is_subscr_msg_sent = false;
        return VS_CODE_OK;
    }

    // If we have just connected to broker then send subscribing message
    if (!(*is_subscr_msg_sent)) {
        char *msg = NULL;

        _make_message(&msg, (uint8_t *)VS_WB_SUBSCR_MESSAGE, strlen(VS_WB_SUBSCR_MESSAGE), false);
        CHECK_RET(NULL != msg, VS_CODE_ERR_QUEUE, "Can't create subscribing message");

        ret = cws_send_text(_websocket_ctx.easy, msg) ? VS_CODE_OK : VS_CODE_ERR_SOCKET;
        VS_LOG_DEBUG("Subscribing message has been sent. %s", msg);
        free(msg);
        CHECK_RET(VS_CODE_OK == ret, VS_CODE_ERR_QUEUE, "Can't send subscribing message");
        *is_subscr_msg_sent = true;
    }

    while (vs_msg_queue_data_present(_queue_ctx)) {
        bool result;
        CHECK_RET(VS_CODE_OK == vs_msg_queue_pop(_queue_ctx, (const void **)&netif, &data, &data_sz),
                  VS_CODE_ERR_QUEUE,
                  "Error while reading message from queue");

        result = cws_send_text(_websocket_ctx.easy, (char *)data);
        free((void *)data);

        if (!result) {
            vs_msg_queue_reset(_queue_ctx);
            return VS_CODE_ERR_SOCKET;
        }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static void *
_websocket_pool_socket_processor(void *param) {
    (void)param;
    vs_status_e res;
    vs_event_bits_t stat = 0;
    vs_log_thread_descriptor("ws poll");

    VS_LOG_DEBUG("Poll thread enter");

    res = _websocket_connect();
    if (VS_CODE_ERR_DEINIT_SNAP == res) {
        VS_LOG_WARNING("Interface has been cancelled during connect");
        goto terminate;
    } else if (VS_CODE_OK != res) {
        VS_LOG_ERROR("Fatal error during websocket connection");
        return NULL;
    }

    while (1) {
        VS_LOG_DEBUG("Websocket has been connected successfully");

        stat = 0;
        struct pollfd pfd;
        bool is_poll = true;
        pfd.fd = _websocket_ctx.sockfd;
        pfd.events = POLLIN | POLLHUP | POLLRDNORM;
        pfd.revents = 0;
        bool is_subscr_msg_sent = false;

        while (is_poll && 0 == stat) {
            int poll_stat;
            res = _message_queue_processing(&is_subscr_msg_sent);
            VS_IOT_ASSERT(VS_CODE_OK == res);
            // call poll with a timeout of 10 ms
            poll_stat = poll(&pfd, 1, 100);
            if (poll_stat > 0) {
                // if result > 0, this means that there is either data available on the
                // socket, or the socket has been closed
                char buffer;
                if (recv(_websocket_ctx.sockfd, &buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT) == 0) {
                    // if recv returns zero, that means the connection has been closed:
                    // cleanup resources and go to reconnect
                    VS_LOG_WARNING("Socket has been closed suddenly");
                    is_poll = false;
                }
            } else if (poll_stat < 0) {
                VS_LOG_WARNING("Connection is lost");
                is_poll = false;
            }

            stat = vs_event_group_wait_bits(
                    &_websocket_ctx.ws_events, WS_EVF_STOP_ALL_THREADS | WS_EVF_PERFORM_THREAD_EXIT, true, false, 0);
        }

        if (stat & WS_EVF_STOP_ALL_THREADS) {
            break;
        }

        res = _websocket_reconnect(stat);
        if (VS_CODE_ERR_DEINIT_SNAP == res) {
            VS_LOG_WARNING("Interface has been cancelled during reconnect");
            break;
        } else if (VS_CODE_OK != res) {
            VS_LOG_ERROR("Fatal error during websocket reconnection");
            return NULL;
        }
    }

terminate:
    vs_event_group_set_bits(&_websocket_ctx.ws_events, WS_EVF_STOP_PERFORM_THREAD);
    pthread_join(curl_perform_loop_thread, NULL);
    VS_LOG_DEBUG("_websocket_pool_socket_processor. Perform thread has been stopped");

    _cws_cleanup_resources();
    curl_multi_cleanup(_websocket_ctx.multi);
    VS_LOG_DEBUG("Poll thread exit");
    return NULL;
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
    CHECK_NOT_ZERO_RET(frame, false);

    struct json_str json;
    json_str_init(&json, frame, frame_size);
    json_start_object(&json);

    json_set_val_str(&json, VS_WB_ACCOUNT_ID_FIELD, _account);

    json_set_val_int(&json, "s", is_stat ? 1 : 0);

    int base64_sz = base64encode_len(data_sz);
    char *data_b64 = (char *)malloc(base64_sz);
    base64encode((const unsigned char *)data, data_sz, data_b64, &base64_sz);
    json_set_val_str(&json, VS_WB_PAYLOAD_FIELD, data_b64);
    free(data_b64);
    json_close_object(&json);

    *message = (char *)json.buff;
    return true;
}

/******************************************************************************/
static vs_status_e
_websock_tx(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    vs_status_e ret;
    char *msg = NULL;

    CHECK_RET(_websocket_ctx.is_initialized, VS_CODE_ERR_TX_SNAP, "Websocket iface is not initialized");
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    // We will have to drop the message if a connection isn't established for a long time, so as not to block the thread
    CHECK_RET(!vs_msg_queue_is_full(_queue_ctx), VS_CODE_ERR_TX_SNAP, "Can't send message because of a queue is full");

    CHECK_RET(_make_message(&msg, data, data_sz, false), VS_CODE_ERR_TX_SNAP, "[WS] Unable to create websocket frame");
    CHECK_NOT_ZERO_RET(msg, VS_CODE_ERR_TX_SNAP);

    ret = vs_msg_queue_push(_queue_ctx, netif, (uint8_t *)msg, strlen(msg) + 1);
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

    CHECK_RET(
            0 == vs_event_group_init(&_websocket_ctx.ws_events), VS_CODE_ERR_INIT_SNAP, "Can't initialize event group");

    _queue_ctx = vs_msg_queue_init(WS_QUEUE_SZ, 1, 1);
    if (!_queue_ctx) {
        VS_LOG_ERROR("Cannot create message queue.");
        vs_event_group_destroy(&_websocket_ctx.ws_events);
        return VS_CODE_ERR_THREAD;
    }

    // Start receive thread
    if (0 == pthread_create(&socket_pool_thread, NULL, _websocket_pool_socket_processor, NULL)) {
        _websocket_ctx.is_initialized = true;
        return VS_CODE_OK;
    }

    vs_msg_queue_free(_queue_ctx);
    vs_event_group_destroy(&_websocket_ctx.ws_events);

    return VS_CODE_ERR_SOCKET;
}

/******************************************************************************/
static vs_status_e
_websock_deinit(struct vs_netif_t *netif) {
    (void)netif;
    if (_websocket_ctx.is_initialized) {
        _websocket_ctx.is_initialized = false;
        VS_LOG_DEBUG("_websock_deinit");
        vs_event_bits_t stat =
                vs_event_group_wait_bits(&_websocket_ctx.ws_events, WS_EVF_SOCKET_CONNECTED, false, false, 0);

        if (stat & WS_EVF_SOCKET_CONNECTED) {
            cws_close(_websocket_ctx.easy, CWS_CLOSE_REASON_NORMAL, "close it!", SIZE_MAX);
        }
        vs_event_group_set_bits(&_websocket_ctx.ws_events, WS_EVF_STOP_ALL_THREADS);
        pthread_join(socket_pool_thread, NULL);
        vs_event_group_destroy(&_websocket_ctx.ws_events);

        vs_msg_queue_free(_queue_ctx);

        free(_url);
        _url = NULL;
        free(_account);
        _account = NULL;
    }

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

    if (NULL == _url || NULL == _account) {
        VS_LOG_ERROR("[WS] Can't allocate memory for websocket creds");
        return NULL;
    }

    return &_netif_websock;
}
/******************************************************************************/