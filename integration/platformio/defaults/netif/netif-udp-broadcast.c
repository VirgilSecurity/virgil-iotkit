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

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
//#include <sys/socket.h>
#include <defaults/netif/netif-udp-broadcast.h>
#include <platform/init/idf/udp_socket.h>
#include <platform/init/idf/wifi_network.h>

#include <virgil/iot/logger/logger.h>

static vs_status_e
_udp_bcast_init(struct vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb);

static vs_status_e
_udp_bcast_deinit(struct vs_netif_t *netif);

static vs_status_e
_udp_bcast_tx(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);

static vs_status_e
_udp_bcast_mac(const struct vs_netif_t *netif, struct vs_mac_addr_t *mac_addr);

static vs_netif_t _netif_udp_bcast = {.user_data = NULL,
                                      .init = _udp_bcast_init,
                                      .deinit = _udp_bcast_deinit,
                                      .tx = _udp_bcast_tx,
                                      .mac_addr = _udp_bcast_mac,
                                      .packet_buf_filled = 0};

static vs_netif_rx_cb_t _netif_udp_bcast_rx_cb = 0;
static vs_netif_process_cb_t _netif_udp_bcast_process_cb = 0;

static bool _active = false;

#define UDP_BCAST_PORT (4100)

#define RX_BUF_SZ (2048)

//******************************************************************************
void
udp_server_recv_cb(struct sockaddr_in from_source, uint8_t *rx_buffer, uint16_t recv_size) {
    const uint8_t *packet_data = NULL;
    uint16_t packet_data_sz = 0;

    char addr_str[128];
    inet_ntoa_r(((struct sockaddr_in *)&from_source)->sin_addr.s_addr, addr_str, sizeof(addr_str) - 1);
    VS_LOG_DEBUG("Received %d bytes from %s:", recv_size, addr_str);

    if (recv_size > 0) {
        if (_netif_udp_bcast_rx_cb) {
            if (0 == _netif_udp_bcast_rx_cb(&_netif_udp_bcast, rx_buffer, recv_size, &packet_data, &packet_data_sz)) {
                // Ready to process packet
                if (_netif_udp_bcast_process_cb) {
                    VS_LOG_HEX(VS_LOGLEV_DEBUG, "RECV DUMP:", packet_data, packet_data_sz);
                    _netif_udp_bcast_process_cb(&_netif_udp_bcast, packet_data, packet_data_sz);
                }
            }
        }
    }
}
/******************************************************************************/
static vs_status_e
_udp_bcast_tx(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    if (!_active) {
        return VS_CODE_ERR_INCORRECT_SEND_REQUEST;
    }
    VS_LOG_DEBUG("Prepare UDP sending: [%d]", (int)data_sz);
    if (udp_socket_send_broadcast(data, data_sz, 0) < 0) {
        return VS_CODE_ERR_SOCKET;
    }
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_udp_bcast_init(struct vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb) {
    assert(rx_cb);
    _netif_udp_bcast_rx_cb = rx_cb;
    _netif_udp_bcast_process_cb = process_cb;
    _netif_udp_bcast.packet_buf_filled = 0;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_udp_bcast_deinit(struct vs_netif_t *netif) {
    //...
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_udp_bcast_mac(const struct vs_netif_t *netif, struct vs_mac_addr_t *mac_addr) {
    uint8_t mac[6];
    wifi_get_mac(mac);
    if (mac_addr) {
        memcpy(mac_addr->bytes, mac, sizeof(mac));
        return VS_CODE_OK;
    }

    return VS_CODE_ERR_NULLPTR_ARGUMENT;
}

/******************************************************************************/
vs_netif_t *
vs_hal_netif_udp_bcast(void) {
    return &_netif_udp_bcast;
}

/******************************************************************************/
void
vs_hal_netif_udp_bcast_set_active(bool is_active) {
    _active = is_active;
}

/******************************************************************************/