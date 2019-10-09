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

#ifndef VS_SDMP_STRUCTS_H
#define VS_SDMP_STRUCTS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <virgil/iot/provision/provision.h>

struct vs_netif_t;
struct vs_mac_addr_t;

typedef uint16_t vs_sdmp_transaction_id_t;
typedef uint32_t vs_sdmp_service_id_t;
typedef uint32_t vs_sdmp_element_t;

// Callback for Received data
typedef vs_status_e (*vs_netif_rx_cb_t)(struct vs_netif_t* netif,
    const uint8_t* data,
    const uint16_t data_sz,
    const uint8_t** packet_data,
    uint16_t* packet_data_sz);

// Callback for Preprocessed data
typedef vs_status_e (*vs_netif_process_cb_t)(struct vs_netif_t* netif, const uint8_t* data, const uint16_t data_sz);

typedef vs_status_e (*vs_netif_tx_t)(const uint8_t* data, const uint16_t data_sz);
typedef vs_status_e (*vs_netif_mac_t)(struct vs_mac_addr_t* mac_addr);

typedef vs_status_e (*vs_netif_init_t)(const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb);

typedef vs_status_e (*vs_netif_deinit_t)(void);

// SDMP Services processor
typedef vs_status_e (*vs_sdmp_service_request_processor_t)(const struct vs_netif_t* netif,
    vs_sdmp_element_t element_id,
    const uint8_t* request,
    const uint16_t request_sz,
    uint8_t* response,
    const uint16_t response_buf_sz,
    uint16_t* response_sz);

typedef vs_status_e (*vs_sdmp_service_response_processor_t)(const struct vs_netif_t* netif,
    vs_sdmp_element_t element_id,
    bool is_ack,
    const uint8_t* response,
    const uint16_t response_sz);

typedef vs_status_e (*vs_sdmp_service_periodical_processor_t)(void);

typedef enum {
    VS_SDMP_DEV_GATEWAY = HTONL_IN_COMPILE_TIME(0x0001),
    VS_SDMP_DEV_THING = HTONL_IN_COMPILE_TIME(0x0002),
    VS_SDMP_DEV_CONTROL = HTONL_IN_COMPILE_TIME(0x0004),
    VS_SDMP_DEV_LOGGER = HTONL_IN_COMPILE_TIME(0x0008),
    VS_SDMP_DEV_SNIFFER = HTONL_IN_COMPILE_TIME(0x0010),
    VS_SDMP_DEV_DEBUGGER = HTONL_IN_COMPILE_TIME(0x0020),
    VS_SDMP_DEV_INITIALIZER = HTONL_IN_COMPILE_TIME(0x0040)
} vs_sdmp_device_role_e;

#define ETH_ADDR_LEN (6)
#define ETH_TYPE_LEN (2)
#define ETH_CRC_LEN (4)
#define ETH_HEADER_LEN (ETH_ADDR_LEN + ETH_ADDR_LEN + ETH_TYPE_LEN)
#define ETH_MIN_LEN (64)
#define ETH_MTU (1500)

#define VS_ETHERTYPE_VIRGIL (HTONS_IN_COMPILE_TIME(0xABCD))

typedef enum {
    VS_SDMP_FLAG_ACK = HTONL_IN_COMPILE_TIME(0x0001),
    VS_SDMP_FLAG_NACK = HTONL_IN_COMPILE_TIME(0x0002)
} vs_sdmp_flags_e;

/******************************************************************************/
typedef struct __attribute__((__packed__)) vs_mac_addr_t {
    uint8_t bytes[ETH_ADDR_LEN];
} vs_mac_addr_t;

/******************************************************************************/
typedef struct __attribute__((__packed__)) ethernet_header {
    vs_mac_addr_t dest;
    vs_mac_addr_t src;
    uint16_t type;
} vs_ethernet_header_t;

/******************************************************************************/
typedef struct __attribute__((__packed__)) {
    vs_sdmp_transaction_id_t transaction_id;
    vs_sdmp_service_id_t service_id; // CODEGEN: SKIP
    vs_sdmp_element_t element_id; // CODEGEN: SKIP
    uint32_t flags; // CODEGEN: SKIP
    uint16_t padding;
    uint16_t content_size;
} vs_sdmp_header_t;

/******************************************************************************/
typedef struct __attribute__((__packed__)) {
    vs_ethernet_header_t eth_header;
    vs_sdmp_header_t header;
    uint8_t content[];
} vs_sdmp_packet_t;

/******************************************************************************/
typedef struct vs_netif_t {
    void* user_data;

    // Functions
    vs_netif_init_t init;
    vs_netif_deinit_t deinit;
    vs_netif_tx_t tx;
    vs_netif_mac_t mac_addr;

    // Incoming packet
    uint8_t packet_buf[1024];
    uint16_t packet_buf_filled;
} vs_netif_t;

/******************************************************************************/
typedef struct {
    void* user_data;
    vs_sdmp_service_id_t id;
    vs_sdmp_service_request_processor_t request_process;
    vs_sdmp_service_response_processor_t response_process;
    vs_sdmp_service_periodical_processor_t periodical_process;
} vs_sdmp_service_t;

/******************************************************************************/
typedef struct {
    uint32_t sent;
    uint32_t received;
} vs_sdmp_stat_t;

/******************************************************************************/

#endif // VS_SDMP_STRUCTS_H
