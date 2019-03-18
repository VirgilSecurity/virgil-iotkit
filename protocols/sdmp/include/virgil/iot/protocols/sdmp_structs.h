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

#ifndef KUNLUN_SDMP_STRUCTS_H
#define KUNLUN_SDMP_STRUCTS_H

typedef struct {
//    /// An opaque context likely used to point to a simulated device context
//    void        *netif_user_data;
//    /// A function that returns the parsed destination and source addresses from a buffer pointing to an interface header
//    int (* parse_hw_header) (uint8_t *pdu, uint8_t *dst, uint8_t *src);
//    /// A function that writes the given destination and protocol information to a buffer - typically used just prior to transmit
//    int (* write_hw_header) (netif_t * netif, uint8_t *pdu, const void * const dest, protocol_t protocol);
//    int (* interface_match) (netif_t * netif, uint8_t * pdu, size_t len, void*);
//    /// A function, that handles common transmit functionality for interfaces of the same type, simulated or not
//    int (* tx) (netif_t * netif, uint8_t * pdu, uint16_t len, void*, netif_t * src_netif);
//    /// A function that performs the real transmission - either on a real or simulated medium
//    int (* hw_tx) (netif_t * netif, uint8_t * data, size_t length, void*, netif_t *src_netif);
//    /// Maximum transmission unit
    uint32_t        mtu;
//    /// Minimum frame length, used to ensure enough zero padding
//    uint32_t        min_len;
//    /// number of frames transmitted
//    uint32_t        stats_tx_count;
//    /// number of frames received
//    uint32_t        stats_rx_count;
//    /// number of dropped frames (queue full)
//    uint32_t        stats_dropped_frames;
//    /// length of interface header
//    uint16_t        hw_header_len;
//    /// current state
//    netif_state     state;
//    /// type of the interface
//    netif_type      type;
//    /// lenght of addresses on the interface
//    uint8_t     hw_addr_len;
//    /// a buffer pointing to the address of this interface
//    uint8_t     hw_addr[MAX_ADDR_LEN];
//    /// a bufer pointing to the broadcast address of this interface
//    uint8_t     brcst_addr[MAX_ADDR_LEN];
} vs_netif_t;

#endif //KUNLUN_SDMP_STRUCTS_H
