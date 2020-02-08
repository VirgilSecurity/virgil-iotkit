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

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/logger/logger.h>

#include "netif/curl-websocket.h"

static vs_status_e
_websock_init(vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb);

static vs_status_e
_websock_deinit(const vs_netif_t *netif);

static vs_status_e
_websock_tx(const vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);

static vs_status_e
_websock_mac(const vs_netif_t *netif, struct vs_mac_addr_t *mac_addr);

static vs_netif_t _netif_websock = {.user_data = NULL,
                                    .init = _websock_init,
                                    .deinit = _websock_deinit,
                                    .tx = _websock_tx,
                                    .mac_addr = _websock_mac,
                                    .packet_buf_filled = 0};

static vs_netif_rx_cb_t _websock_rx_cb = 0;
static vs_netif_process_cb_t _websock_process_cb = 0;
static char *_url = NULL;
static char *_account = NULL;

// static pthread_t receive_thread;
static uint8_t _sim_mac_addr[6] = {2, 2, 2, 2, 2, 2};

#define RX_BUF_SZ (2048)

struct myapp_ctx {
    CURL *easy;
    CURLM *multi;
    int text_lines;
    int binary_lines;
    int exitval;
    bool running;
};

/******************************************************************************/
static bool
send_dummy(CURL *easy, bool text, size_t lines) {
    size_t len = lines * 80;
    char *buf = malloc(len);
    const size_t az_range = 'Z' - 'A';
    size_t i;
    bool ret;

    for (i = 0; i < lines; i++) {
        char *ln = buf + i * 80;
        uint8_t chr;

        snprintf(ln, 11, "%9zd ", i + 1);
        if (text)
            chr = (i % az_range) + 'A';
        else
            chr = i & 0xff;
        memset(ln + 10, chr, 69);
        ln[79] = '\n';
    }

    ret = cws_send(easy, text, buf, len);
    free(buf);
    return ret;
}

/******************************************************************************/
static void
on_connect(void *data, CURL *easy, const char *websocket_protocols) {
    struct myapp_ctx *ctx = data;
    fprintf(stderr, "INFO: connected, websocket_protocols='%s'\n", websocket_protocols);
    send_dummy(easy, true, ++ctx->text_lines);
}

/******************************************************************************/
static void
on_text(void *data, CURL *easy, const char *text, size_t len) {
    struct myapp_ctx *ctx = data;
    fprintf(stderr, "INFO: TEXT={\n%s\n}\n", text);

    if (ctx->text_lines < 5)
        send_dummy(easy, true, ++ctx->text_lines);
    else
        send_dummy(easy, false, ++ctx->binary_lines);

    (void)len;
}

/******************************************************************************/
static void
on_binary(void *data, CURL *easy, const void *mem, size_t len) {
    struct myapp_ctx *ctx = data;
    const uint8_t *bytes = mem;
    size_t i;

    fprintf(stderr, "INFO: BINARY=%zd bytes {\n", len);

    for (i = 0; i < len; i++) {
        uint8_t b = bytes[i];
        if (isprint(b))
            fprintf(stderr, " %#04x(%c)", b, b);
        else
            fprintf(stderr, " %#04x", b);
    }

    fprintf(stderr, "\n}\n");

    if (ctx->binary_lines < 5)
        send_dummy(easy, false, ++ctx->binary_lines);
    else
        cws_ping(easy, "will close on pong", SIZE_MAX);
}

/******************************************************************************/
static void
on_ping(void *data, CURL *easy, const char *reason, size_t len) {
    fprintf(stderr, "INFO: PING %zd bytes='%s'\n", len, reason);
    cws_pong(easy, "just pong", SIZE_MAX);
    (void)data;
}

/******************************************************************************/
static void
on_pong(void *data, CURL *easy, const char *reason, size_t len) {
    fprintf(stderr, "INFO: PONG %zd bytes='%s'\n", len, reason);

    cws_close(easy, CWS_CLOSE_REASON_NORMAL, "close it!", SIZE_MAX);
    (void)data;
    (void)easy;
}

/******************************************************************************/
static void
on_close(void *data, CURL *easy, enum cws_close_reason reason, const char *reason_text, size_t reason_text_len) {
    struct myapp_ctx *ctx = data;
    fprintf(stderr, "INFO: CLOSE=%4d %zd bytes '%s'\n", reason, reason_text_len, reason_text);

    ctx->exitval = (reason == CWS_CLOSE_REASON_NORMAL ? EXIT_SUCCESS : EXIT_FAILURE);
    ctx->running = false;
    (void)easy;
}

/******************************************************************************/
// static void *
//_udp_bcast_receive_processor(void *sock_desc) {
//    static uint8_t received_data[RX_BUF_SZ];
//    struct sockaddr_in client_addr;
//    ssize_t recv_sz;
//    socklen_t addr_sz = sizeof(struct sockaddr_in);
//    const uint8_t *packet_data = NULL;
//    uint16_t packet_data_sz = 0;
//
//    while (1) {
//        memset(received_data, 0, RX_BUF_SZ);
//
//        recv_sz = recvfrom(
//                _udp_bcast_sock, received_data, sizeof received_data, 0, (struct sockaddr *)&client_addr, &addr_sz);
//        if (recv_sz < 0) {
//            VS_LOG_ERROR("UDP broadcast: recv stop");
//            break;
//        }
//
//        if (!recv_sz) {
//            continue;
//        }
//
//        // Pass received data to upper level via callback
//        if (_netif_udp_bcast_rx_cb) {
//            if (0 == _netif_udp_bcast_rx_cb(&_netif_udp_bcast, received_data, recv_sz, &packet_data, &packet_data_sz))
//            {
//                // Ready to process packet
//                if (_netif_udp_bcast_process_cb) {
//                    _netif_udp_bcast_process_cb(&_netif_udp_bcast, packet_data, packet_data_sz);
//                }
//            }
//        }
//    }
//
//    return NULL;
//}

/******************************************************************************/
static vs_status_e
_websock_connect() {
    //    struct sockaddr_in server;
    //    struct timeval tv;
    //    int enable = 1;

    struct myapp_ctx myapp_ctx = {
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
            .data = &myapp_ctx,
    };

    curl_global_init(CURL_GLOBAL_DEFAULT);

    myapp_ctx.easy = cws_new(url, protocols, &cbs);
    if (!myapp_ctx.easy)
        goto error_easy;

    /* here you should do any extra sets, like cookies, auth... */
    curl_easy_setopt(myapp_ctx.easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(myapp_ctx.easy, CURLOPT_VERBOSE, 1L);

    /*
     * This is a traditional curl_multi app, see:
     *
     * https://curl.haxx.se/libcurl/c/multi-app.html
     */
    myapp_ctx.multi = curl_multi_init();
    if (!myapp_ctx.multi)
        goto error_multi;

    curl_multi_add_handle(myapp_ctx.multi, myapp_ctx.easy);

    myapp_ctx.running = true;
    a_main_loop(&myapp_ctx);

    curl_multi_remove_handle(myapp_ctx.multi, myapp_ctx.easy);
    curl_multi_cleanup(myapp_ctx.multi);

error_multi:
    cws_free(myapp_ctx.easy);
error_easy:
    curl_global_cleanup();

    return myapp_ctx.exitval;


    //
    //    // Create socket
    //    _udp_bcast_sock = socket(AF_INET, SOCK_DGRAM, 0);
    //    if (_udp_bcast_sock == -1) {
    //        VS_LOG_ERROR("UDP Broadcast: Could not create socket. %s\n", strerror(errno));
    //        return VS_CODE_ERR_SOCKET;
    //    }
    //
    //    // Set infinite timeout
    //    tv.tv_sec = 0;
    //    tv.tv_usec = 0;
    //    if (setsockopt(_udp_bcast_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    //        VS_LOG_ERROR("UDP Broadcast: Cannot set infinite timeout on receive. %s\n", strerror(errno));
    //        goto terminate;
    //    }
    //
    //#if __APPLE__
    //    // Set SO_REUSEPORT
    //    if (setsockopt(_udp_bcast_sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
    //        VS_LOG_ERROR("UDP Broadcast: Cannot set SO_REUSEPORT. %s\n", strerror(errno));
    //        goto terminate;
    //    }
    //#else
    //    // Set SO_REUSEADDR
    //    if (setsockopt(_udp_bcast_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    //        printf("UDP Broadcast: Cannot set SO_REUSEADDR. %s\n", strerror(errno));
    //        goto terminate;
    //    }
    //#endif
    //
    //    // Set SO_BROADCAST
    //    if (setsockopt(_udp_bcast_sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(int)) < 0) {
    //        VS_LOG_ERROR("UDP Broadcast: Cannot set SO_BROADCAST. %s\n", strerror(errno));
    //        goto terminate;
    //    }
    //
    //    // Bind to port
    //    memset((void *)&server, 0, sizeof(struct sockaddr_in));
    //    server.sin_family = AF_INET;
    //    server.sin_addr.s_addr = htons(INADDR_ANY);
    //    server.sin_port = htons(UDP_BCAST_PORT);
    //    if (bind(_udp_bcast_sock, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
    //        VS_LOG_ERROR("UDP Broadcast: UDP Broadcast: Bind error. %s\n", strerror(errno));
    //        goto terminate;
    //    }
    //
    //    VS_LOG_INFO("Opened connection for UDP broadcast\n");
    //
    //    // Start receive thread
    //    pthread_create(&receive_thread, NULL, _udp_bcast_receive_processor, NULL);
    //
    return VS_CODE_OK;

terminate:

    _websock_deinit(&_netif_websock);

    return VS_CODE_ERR_SOCKET;
}

/******************************************************************************/
static vs_status_e
_websock_tx(const vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    //    struct sockaddr_in broadcast_addr;
    //
    //    memset((void *)&broadcast_addr, 0, sizeof(struct sockaddr_in));
    //    broadcast_addr.sin_family = AF_INET;
    //    broadcast_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    //    broadcast_addr.sin_port = htons(UDP_BCAST_PORT);
    //
    //    sendto(_udp_bcast_sock, data, data_sz, 0, (struct sockaddr *)&broadcast_addr, sizeof(struct sockaddr_in));

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_websock_init(vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb) {
    assert(rx_cb);
    _websock_rx_cb = rx_cb;
    _websock_process_cb = process_cb;
    _netif_websock.packet_buf_filled = 0;

    _websock_connect();

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_websock_deinit(const vs_netif_t *netif) {
    //    if (_udp_bcast_sock >= 0) {
    //#if !defined(__APPLE__)
    //        shutdown(_udp_bcast_sock, SHUT_RDWR);
    //#endif
    //        close(_udp_bcast_sock);
    //    }
    //    _udp_bcast_sock = -1;
    //    pthread_join(receive_thread, NULL);
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_websock_mac(const vs_netif_t *netif, struct vs_mac_addr_t *mac_addr) {

    if (mac_addr) {
        memcpy(mac_addr->bytes, _sim_mac_addr, sizeof(vs_mac_addr_t));
        return VS_CODE_OK;
    }

    return VS_CODE_ERR_NULLPTR_ARGUMENT;
}

/******************************************************************************/
vs_netif_t *
vs_hal_netif_websock(const char *url, const char *account, vs_mac_addr_t mac_addr) {

    CHECK_NOT_ZERO_RET(url, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(account, VS_CODE_ERR_INCORRECT_ARGUMENT);

    memcpy(_sim_mac_addr, mac_addr.bytes, 6);
    free(_url);
    _url = NULL;
    free(_account);
    _account = NULL;
    _url = strdup(url);
    _account = strdup(account);
    return &_netif_websock;
}

/******************************************************************************/