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

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/initializer/hal/netif_plc_sim.h>

#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static int _plc_sock = -1;
static pthread_t receive_thread;
static vs_netif_t _netif_plc_sim = {0};
static bool _netif_plc_ready_sim = false;
static vs_netif_rx_cb_t _netif_plc_rx_cb_sim = 0;

#define PLC_SIM_ADDR "127.0.0.1"
#define PLC_SIM_PORT 3333

#define PLC_RX_BUF_SZ (2048)
#define PLC_RESERVED_SZ (128)

/******************************************************************************/
static void *
_plc_receive_processor(void *sock_desc) {
    char received_data[PLC_RX_BUF_SZ];
    ssize_t recv_sz;

    while (1) {
        recv_sz = recv(_plc_sock, received_data, PLC_RX_BUF_SZ, 0);
        if (recv_sz < 0) {
            printf("PLC recv failed\n");
            break;
        }

        // Pass received data to upper level via callback
        _netif_plc_rx_cb_sim(vs_hal_netif_plc_sim(), (uint8_t*)received_data, recv_sz);
    }

    return NULL;
}

/******************************************************************************/
static int
_plc_tx_sim(const uint8_t *data, const size_t data_sz) {

    if (_plc_sock <= 0) {
        return -1;
    }

    if (data_sz == send(_plc_sock, data, data_sz, 0)) {
        return 0;
    }

    return -1;
}

/******************************************************************************/
static int
_plc_init_sim(const vs_netif_rx_cb_t rx_cb) {
    struct sockaddr_in server;

    _netif_plc_rx_cb_sim = rx_cb;

    // Create socket
    _plc_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_plc_sock == -1) {
        printf("Could not create socket\n");
    }

    server.sin_addr.s_addr = inet_addr(PLC_SIM_ADDR);
    server.sin_family = AF_INET;
    server.sin_port = htons(PLC_SIM_PORT);

    // Connect to remote server
    if (connect(_plc_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connect failed. Error\n");
        return 1;
    }

    printf("Connected to PLC bus\n");

    pthread_create(&receive_thread, NULL, _plc_receive_processor, NULL);

    return 0;
}

/******************************************************************************/
int
_plc_deinit_sim() {
    close(_plc_sock);
    pthread_join(receive_thread, NULL);
    return 0;
}

/******************************************************************************/
int
_plc_mac_sim(struct vs_mac_addr_t *mac_addr) {

    if (mac_addr) {
        memset(mac_addr->bytes, 0x01, sizeof(vs_mac_addr_t));
        return 0;
    }

    return 1;
}

/******************************************************************************/
static void
_prepare_netif_plc_sim() {
    _netif_plc_sim.user_data = NULL;
    _netif_plc_sim.init = _plc_init_sim;
    _netif_plc_sim.deinit = _plc_deinit_sim;
    _netif_plc_sim.tx = _plc_tx_sim;
    _netif_plc_sim.mac_addr = _plc_mac_sim;
}

/******************************************************************************/
const vs_netif_t *
vs_hal_netif_plc_sim() {

    if (!_netif_plc_ready_sim) {
        _prepare_netif_plc_sim();
        _netif_plc_ready_sim = true;
    }

    return &_netif_plc_sim;
}
