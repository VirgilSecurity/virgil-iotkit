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

#include <stdlib-config.h>
#include <virgil/iot/protocols/snap/snap-structs.h>
#include <private/netif_test_impl.h>

netif_state_t netif_state;
vs_mac_addr_t mac_addr_client_call;
vs_mac_addr_t mac_addr_server_call;
bool is_client_call;

static vs_status_e
test_netif_tx(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);
static vs_status_e
test_netif_mac_addr(const struct vs_netif_t *netif, struct vs_mac_addr_t *mac_addr);
static vs_status_e
test_netif_init(struct vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb);
static vs_status_e
test_netif_deinit(struct vs_netif_t *netif);

static vs_netif_t _test_netif = {
        .init = test_netif_init,
        .deinit = test_netif_deinit,
        .mac_addr = test_netif_mac_addr,
        .tx = test_netif_tx,
        .user_data = (void *)&netif_state,
};

static vs_netif_rx_cb_t callback_rx_cb;
static vs_netif_process_cb_t callback_process_cb;

/**********************************************************/
static vs_status_e
test_netif_tx(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    int ret_code = -1;
    const uint8_t *packet_data;
    uint16_t packet_data_sz;

    (void)netif;

    is_client_call = !is_client_call;

    if (0 == callback_rx_cb(&_test_netif, data, data_sz, &packet_data, &packet_data_sz)) {
        ret_code = callback_process_cb(&_test_netif, packet_data, packet_data_sz);
    }

    netif_state.sent = 1;

    return ret_code;
}

/**********************************************************/
static vs_status_e
test_netif_mac_addr(const struct vs_netif_t *netif, struct vs_mac_addr_t *mac_addr) {
    VS_IOT_ASSERT(mac_addr);

    (void)netif;

    *mac_addr = is_client_call ? mac_addr_client_call : mac_addr_server_call;

    netif_state.mac_addr_set_up = 1;

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_e
test_netif_init(struct vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb) {
    VS_IOT_ASSERT(rx_cb);

    (void)netif;

    callback_rx_cb = rx_cb;
    callback_process_cb = process_cb;
    netif_state.deinitialized = 0;
    netif_state.initialized = 1;

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_e
test_netif_deinit(struct vs_netif_t *netif) {
    (void)netif;
    netif_state.initialized = 0;
    netif_state.deinitialized = 1;
    return VS_CODE_OK;
}

/**********************************************************/
vs_netif_t *
vs_test_netif(void) {
    netif_state.membuf = 0;
    return &_test_netif;
}