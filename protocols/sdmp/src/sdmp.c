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

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/sdmp_private.h>
#include "hal/macro.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static const vs_netif_t *_sdmp_default_netif = 0;

#define RESPONSE_SZ_MAX (1024)
#define RESPONSE_RESERVED_SZ (sizeof(vs_sdmp_packet_t))
#define SERVICES_CNT_MAX (10)
static const vs_sdmp_service_t *_sdmp_services[SERVICES_CNT_MAX];
static size_t _sdmp_services_num = 0;

/******************************************************************************/
static int
_sdmp_rx_cb(const vs_netif_t *netif, const uint8_t *data, const size_t data_sz) {
    int i;
    const vs_sdmp_packet_t *packet = (vs_sdmp_packet_t *)data;
    uint8_t response[RESPONSE_SZ_MAX + RESPONSE_RESERVED_SZ];
    size_t response_sz = 0;
    vs_sdmp_packet_t *response_packet = (vs_sdmp_packet_t *)response;
    bool processed = false;

    // Check packet

    // Check is my packet

    // Prepare request
    memcpy(&response_packet->header, &packet->header, sizeof(vs_sdmp_packet_t));
    _sdmp_fill_header(&packet->eth_header.src, response_packet);

    // Detect required command
    for (i = 0; i < _sdmp_services_num; i++) {
        if (_sdmp_services[i]->id == packet->header.service_id) {

            // Process response
            if (packet->header.flags & VS_SDMP_FLAG_ACK || packet->header.flags & VS_SDMP_FLAG_NACK) {
                _sdmp_services[i]->response_process(
                        netif, packet->header.element_id, packet->content, packet->header.content_size);

                // Process request
            } else {
                processed = true;
                if (0 == _sdmp_services[i]->request_process(netif, packet->header.element_id, packet->content,
                                 packet->header.content_size, response_packet->content, RESPONSE_SZ_MAX,
                                 &response_sz)) {
                    // Send response

                    response_packet->header.content_size = response_sz;
                    response_packet->header.flags |= VS_SDMP_FLAG_ACK;
                } else {
                    // Send response with error code
                    response_packet->header.flags |= VS_SDMP_FLAG_NACK;
                    response_packet->header.content_size = 0;
                }
            }
        }
    }

    if (processed) {
        printf("\033[32;1m >>> Send response: %lu <<< \033[0m\n",
                sizeof(vs_sdmp_packet_t) + response_packet->header.content_size);
        vs_sdmp_send(netif, response, sizeof(vs_sdmp_packet_t) + response_packet->header.content_size);
    }

    return -1;
}

/******************************************************************************/
int
vs_sdmp_init(const vs_netif_t *default_netif) {

    // Check input data
    VS_ASSERT(default_netif);
    VS_ASSERT(default_netif->init);
    VS_ASSERT(default_netif->tx);

    // Save default network interface
    _sdmp_default_netif = default_netif;

    // Init default network interface
    default_netif->init(_sdmp_rx_cb);

    return 0;
}

/******************************************************************************/
int
vs_sdmp_send(const vs_netif_t *netif, const uint8_t *data, size_t data_sz) {
    VS_ASSERT(_sdmp_default_netif);
    VS_ASSERT(_sdmp_default_netif->tx);

    if (!netif || netif == _sdmp_default_netif) {
        return _sdmp_default_netif->tx(data, data_sz);
    }

    return -1;
}

/******************************************************************************/
int
vs_sdmp_register_service(const vs_sdmp_service_t *service) {

    VS_ASSERT(service);

    if (_sdmp_services_num >= SERVICES_CNT_MAX) {
        return -1;
    }

    _sdmp_services[_sdmp_services_num] = service;
    _sdmp_services_num++;

    return 0;
}

/******************************************************************************/
int
vs_sdmp_mac_addr(const vs_netif_t *netif, vs_mac_addr_t *mac_addr) {
    VS_ASSERT(mac_addr);

    if (!netif || netif == _sdmp_default_netif) {
        VS_ASSERT(_sdmp_default_netif);
        VS_ASSERT(_sdmp_default_netif->mac_addr);
        _sdmp_default_netif->mac_addr(mac_addr);
        return 0;
    }

    return -1;
}

/******************************************************************************/
vs_sdmp_transaction_id_t
_sdmp_transaction_id() {
    static vs_sdmp_transaction_id_t id = 0;

    return id++;
}

/******************************************************************************/
int
_sdmp_fill_header(const vs_mac_addr_t *recipient_mac, vs_sdmp_packet_t *packet) {

    VS_ASSERT(packet);

    // Ethernet packet type
    packet->eth_header.type = VS_ETHERTYPE_VIRGIL;

    // Fill own MAC address for a default net interface
    vs_sdmp_mac_addr(0, &packet->eth_header.src);

    // Fill recipient MAC address
    if (!recipient_mac) {
        memset(packet->eth_header.dest.bytes, 0xFF, sizeof(vs_mac_addr_t));
    } else {
        memcpy(packet->eth_header.dest.bytes, recipient_mac->bytes, sizeof(vs_mac_addr_t));
    }

    // Transaction ID
    packet->header.transaction_id = _sdmp_transaction_id();

    return 0;
}

/******************************************************************************/