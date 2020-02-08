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

static vs_status_e
_udp_bcast_init(vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb);

static vs_status_e
_udp_bcast_deinit(const vs_netif_t *netif);

static vs_status_e
_udp_bcast_tx(const vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);

static vs_status_e
_udp_bcast_mac(const vs_netif_t *netif, struct vs_mac_addr_t *mac_addr);

static vs_netif_t _netif_udp_bcast = {.user_data = NULL,
                                      .init = _udp_bcast_init,
                                      .deinit = _udp_bcast_deinit,
                                      .tx = _udp_bcast_tx,
                                      .mac_addr = _udp_bcast_mac,
                                      .packet_buf_filled = 0};

static vs_netif_rx_cb_t _netif_udp_bcast_rx_cb = 0;
static vs_netif_process_cb_t _netif_udp_bcast_process_cb = 0;

static int _udp_bcast_sock = -1;
static pthread_t receive_thread;
static uint8_t _sim_mac_addr[6] = {2, 2, 2, 2, 2, 2};

static in_addr_t _dst_addr = INADDR_BROADCAST;

#define UDP_BCAST_PORT (4100)

#define RX_BUF_SZ (2048)

/******************************************************************************/
static void *
_udp_bcast_receive_processor(void *sock_desc) {
    static uint8_t received_data[RX_BUF_SZ];
    struct sockaddr_in client_addr;
    ssize_t recv_sz;
    socklen_t addr_sz = sizeof(struct sockaddr_in);
    const uint8_t *packet_data = NULL;
    uint16_t packet_data_sz = 0;

    vs_log_thread_descriptor("udp bcast thr");

    while (1) {
        memset(received_data, 0, RX_BUF_SZ);

        recv_sz = recvfrom(
                _udp_bcast_sock, received_data, sizeof received_data, 0, (struct sockaddr *)&client_addr, &addr_sz);
        if (recv_sz < 0) {
            VS_LOG_ERROR("UDP broadcast: recv stop");
            break;
        }

        if (!recv_sz) {
            continue;
        }

        // Pass received data to upper level via callback
        if (_netif_udp_bcast_rx_cb) {
            if (0 == _netif_udp_bcast_rx_cb(&_netif_udp_bcast, received_data, recv_sz, &packet_data, &packet_data_sz)) {
                // Ready to process packet
                if (_netif_udp_bcast_process_cb) {
                    _netif_udp_bcast_process_cb(&_netif_udp_bcast, packet_data, packet_data_sz);
                }
            }
        }
    }

    return NULL;
}

/******************************************************************************/
static vs_status_e
_udp_bcast_connect() {
    struct sockaddr_in server;
    struct timeval tv;
    int enable = 1;

    // Create socket
    _udp_bcast_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (_udp_bcast_sock == -1) {
        VS_LOG_ERROR("UDP Broadcast: Could not create socket. %s\n", strerror(errno));
        return VS_CODE_ERR_SOCKET;
    }

    // Set infinite timeout
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (setsockopt(_udp_bcast_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        VS_LOG_ERROR("UDP Broadcast: Cannot set infinite timeout on receive. %s\n", strerror(errno));
        goto terminate;
    }

#if __APPLE__
    // Set SO_REUSEPORT
    if (setsockopt(_udp_bcast_sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
        VS_LOG_ERROR("UDP Broadcast: Cannot set SO_REUSEPORT. %s\n", strerror(errno));
        goto terminate;
    }
#else
    // Set SO_REUSEADDR
    if (setsockopt(_udp_bcast_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        printf("UDP Broadcast: Cannot set SO_REUSEADDR. %s\n", strerror(errno));
        goto terminate;
    }
#endif

    // Set SO_BROADCAST
    if (setsockopt(_udp_bcast_sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(int)) < 0) {
        VS_LOG_ERROR("UDP Broadcast: Cannot set SO_BROADCAST. %s\n", strerror(errno));
        goto terminate;
    }

    // Bind to port
    memset((void *)&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htons(INADDR_ANY);
    server.sin_port = htons(UDP_BCAST_PORT);
    if (bind(_udp_bcast_sock, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
        VS_LOG_ERROR("UDP Broadcast: UDP Broadcast: Bind error. %s\n", strerror(errno));
        goto terminate;
    }

    VS_LOG_INFO("Opened connection for UDP broadcast\n");

    // Start receive thread
    pthread_create(&receive_thread, NULL, _udp_bcast_receive_processor, NULL);

    return VS_CODE_OK;

terminate:

    _udp_bcast_deinit(&_netif_udp_bcast);

    return VS_CODE_ERR_SOCKET;
}

/******************************************************************************/
static vs_status_e
_udp_bcast_tx(const vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    struct sockaddr_in broadcast_addr;
    (void)netif;

    memset((void *)&broadcast_addr, 0, sizeof(struct sockaddr_in));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = _dst_addr;
    broadcast_addr.sin_port = htons(UDP_BCAST_PORT);

    sendto(_udp_bcast_sock, data, data_sz, 0, (struct sockaddr *)&broadcast_addr, sizeof(struct sockaddr_in));

    return VS_CODE_OK;
}

/******************************************************************************/
static void
_prepare_dst_addr(void) {
    const char *_bcast_addr_str = getenv("VS_BCAST_SUBNET_ADDR");
    if (!_bcast_addr_str) {
        VS_LOG_INFO("VS_BCAST_SUBNET_ADDR = 255.255.255.255");
        _dst_addr = INADDR_BROADCAST;
        return;
    }

    VS_LOG_INFO("VS_BCAST_SUBNET_ADDR = %s", _bcast_addr_str);
    _dst_addr = inet_addr(_bcast_addr_str);
}

/******************************************************************************/
static vs_status_e
_udp_bcast_init(vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb) {
    assert(rx_cb);
    (void)netif;
    _netif_udp_bcast_rx_cb = rx_cb;
    _netif_udp_bcast_process_cb = process_cb;
    _netif_udp_bcast.packet_buf_filled = 0;
    _prepare_dst_addr();
    _udp_bcast_connect();

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_udp_bcast_deinit(const vs_netif_t *netif) {
    (void)netif;
    if (_udp_bcast_sock >= 0) {
#if !defined(__APPLE__)
        shutdown(_udp_bcast_sock, SHUT_RDWR);
#endif
        close(_udp_bcast_sock);
    }
    _udp_bcast_sock = -1;
    pthread_join(receive_thread, NULL);
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_udp_bcast_mac(const vs_netif_t *netif, struct vs_mac_addr_t *mac_addr) {
    (void)netif;

    if (mac_addr) {
        memcpy(mac_addr->bytes, _sim_mac_addr, sizeof(vs_mac_addr_t));
        return VS_CODE_OK;
    }

    return VS_CODE_ERR_NULLPTR_ARGUMENT;
}

/******************************************************************************/
vs_netif_t *
vs_hal_netif_udp_bcast(vs_mac_addr_t mac_addr) {
    memcpy(_sim_mac_addr, mac_addr.bytes, 6);
    return &_netif_udp_bcast;
}

/******************************************************************************/