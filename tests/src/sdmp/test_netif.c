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

#include <stdlib-config.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/tests/private/test_netif.h>

netif_state_t netif_state;
vs_mac_addr_t mac_addr_client_call;
vs_mac_addr_t mac_addr_server_call;
bool is_client_call;

static vs_netif_t *test_netif = NULL;
static vs_netif_rx_cb_t callback_rx_cb;
static vs_netif_process_cb_t callback_process_cb;

/**********************************************************/
static int
test_netif_tx(const uint8_t *data, const uint16_t data_sz) {
    int ret_code = -1;
    const uint8_t *packet_data;
    uint16_t packet_data_sz;

    is_client_call = !is_client_call;

    if (0 == callback_rx_cb(test_netif, data, data_sz, &packet_data, &packet_data_sz)) {
        ret_code = callback_process_cb(test_netif, packet_data, packet_data_sz);
    }

    netif_state.sent = 1;

    return ret_code;
}

/**********************************************************/
static int
test_netif_mac_addr(struct vs_mac_addr_t *mac_addr) {
    VS_IOT_ASSERT(mac_addr);

    *mac_addr = is_client_call ? mac_addr_client_call : mac_addr_server_call;

    netif_state.mac_addr_set_up = 1;

    return 0;
}

/**********************************************************/
static int
test_netif_init(const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb) {
    VS_IOT_ASSERT(rx_cb);

    callback_rx_cb = rx_cb;
    callback_process_cb = process_cb;

    netif_state.initialized = 1;

    return 0;
}

/**********************************************************/
static int
test_netif_deinit() {
    netif_state.deinitialized = 1;
    return 0;
}

/**********************************************************/
void
prepare_test_netif(vs_netif_t *netif) {
    VS_IOT_ASSERT(netif);

    test_netif = netif;

    netif->user_data = (void *)&netif_state;

    netif->tx = test_netif_tx;
    netif->mac_addr = test_netif_mac_addr;
    netif->init = test_netif_init;
    netif->deinit = test_netif_deinit;

    netif_state.membuf = 0;
}
