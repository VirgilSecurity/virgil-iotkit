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
static uint8_t _sdmp_broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/******************************************************************************/
static bool
_is_broadcast(const vs_mac_addr_t *mac_addr) {
    return 0 == memcmp(mac_addr->bytes, _sdmp_broadcast_mac, ETH_ADDR_LEN);
}

/******************************************************************************/
static bool
_is_my_mac(const vs_netif_t *netif, const vs_mac_addr_t *mac_addr) {
    vs_mac_addr_t netif_mac_addr;
    netif->mac_addr(&netif_mac_addr);

    return 0 == memcmp(mac_addr->bytes, netif_mac_addr.bytes, ETH_ADDR_LEN);
}

/******************************************************************************/
static bool
_accept_packet(const vs_netif_t *netif, const vs_mac_addr_t *mac_addr) {
    return _is_broadcast(mac_addr) || _is_my_mac(netif, mac_addr);
}

/******************************************************************************/
static int
_process_packet(const vs_netif_t *netif, const vs_sdmp_packet_t *packet) {
    int i;
    uint8_t response[RESPONSE_SZ_MAX + RESPONSE_RESERVED_SZ];
    size_t response_sz = 0;
    vs_sdmp_packet_t *response_packet = (vs_sdmp_packet_t *)response;
    bool processed = false;

    // Check packet

    // Check is my packet
    if (!_accept_packet(netif, &packet->eth_header.dest)) {
        return -1;
    }

    // Prepare request
    memcpy(&response_packet->header, &packet->header, sizeof(vs_sdmp_packet_t));
    _sdmp_fill_header(&packet->eth_header.src, response_packet);

    // Detect required command
    for (i = 0; i < _sdmp_services_num; i++) {
        if (_sdmp_services[i]->id == packet->header.service_id) {

            // Process response
            if (packet->header.flags & VS_SDMP_FLAG_ACK || packet->header.flags & VS_SDMP_FLAG_NACK) {
                _sdmp_services[i]->response_process(netif,
                                                    packet->header.element_id,
                                                    packet->header.flags & VS_SDMP_FLAG_ACK,
                                                    packet->content,
                                                    packet->header.content_size);

                // Process request
            } else {
                processed = true;
                if (0 == _sdmp_services[i]->request_process(netif,
                                                            packet->header.element_id,
                                                            packet->content,
                                                            packet->header.content_size,
                                                            response_packet->content,
                                                            RESPONSE_SZ_MAX,
                                                            &response_sz)) {
                    // Send response
                    response_packet->header.content_size = response_sz;
                    response_packet->header.flags |= VS_SDMP_FLAG_ACK;
                } else {
                    // Send response with error code
                    // TODO: Fill structure with error code here
                    response_packet->header.flags |= VS_SDMP_FLAG_NACK;
                    response_packet->header.content_size = 0;
                }
            }
        }
    }

    if (processed) {
        vs_sdmp_send(netif, response, sizeof(vs_sdmp_packet_t) + response_packet->header.content_size);
    }

    return -1;
}

/******************************************************************************/
static size_t
_packet_sz(const uint8_t *packet_data) {
    const vs_sdmp_packet_t *packet = (vs_sdmp_packet_t *)packet_data;
    return sizeof(vs_sdmp_packet_t) + packet->header.content_size;
}

/******************************************************************************/
static int
_sdmp_rx_cb(const vs_netif_t *netif, const uint8_t *data, const size_t data_sz) {
#define LEFT_INCOMING ((int)data_sz - bytes_processed)
    static uint8_t packet_buf[1024];
    static size_t packet_buf_filled = 0;

    int bytes_processed = 0;
    int need_bytes_for_header;
    int need_bytes_for_packet;
    size_t packet_sz;
    size_t copy_bytes;

    const vs_sdmp_packet_t *packet = 0;

    while (LEFT_INCOMING) {

        if (!packet_buf_filled) {
            if (LEFT_INCOMING >= sizeof(vs_sdmp_packet_t)) {
                packet_sz = _packet_sz(&data[bytes_processed]);

                if (LEFT_INCOMING < packet_sz) {
                    memcpy(&packet_buf[packet_buf_filled], &data[bytes_processed], LEFT_INCOMING);
                    packet_buf_filled += LEFT_INCOMING;
                    bytes_processed += LEFT_INCOMING;
                } else {
                    packet = (vs_sdmp_packet_t *)&data[bytes_processed];
                    bytes_processed += packet_sz;
                }
            } else {
                memcpy(&packet_buf[packet_buf_filled], &data[bytes_processed], LEFT_INCOMING);
                packet_buf_filled += LEFT_INCOMING;
                bytes_processed += LEFT_INCOMING;
            }

        } else {

            // Fill packet struct
            if (packet_buf_filled < sizeof(vs_sdmp_packet_t)) {
                need_bytes_for_header = sizeof(vs_sdmp_packet_t) - packet_buf_filled;

                copy_bytes = LEFT_INCOMING >= need_bytes_for_header ? need_bytes_for_header : LEFT_INCOMING;
                memcpy(&packet_buf[packet_buf_filled], &data[bytes_processed], copy_bytes);
                bytes_processed += copy_bytes;
                packet_buf_filled += copy_bytes;
            }

            // Fill content
            if (packet_buf_filled >= sizeof(vs_sdmp_packet_t)) {
                packet_sz = _packet_sz(packet_buf);

                need_bytes_for_packet = packet_sz - packet_buf_filled;

                copy_bytes = LEFT_INCOMING >= need_bytes_for_packet ? need_bytes_for_packet : LEFT_INCOMING;
                memcpy(&packet_buf[packet_buf_filled], &data[bytes_processed], copy_bytes);
                bytes_processed += copy_bytes;
                packet_buf_filled += copy_bytes;

                if (packet_buf_filled >= packet_sz) {
                    packet = (vs_sdmp_packet_t *)packet_buf;
                }
            }
        }

        if (packet) {
            _process_packet(netif, packet);
            packet = 0;
            packet_buf_filled = 0;
        }
    }

    return 0;
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
vs_sdmp_deinit() {
    VS_ASSERT(_sdmp_default_netif);
    VS_ASSERT(_sdmp_default_netif->deinit);

    _sdmp_default_netif->deinit();

    _sdmp_services_num = 0;

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
int _sdmp_fill_header(const vs_mac_addr_t *recipient_mac, vs_sdmp_packet_t *packet) {

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