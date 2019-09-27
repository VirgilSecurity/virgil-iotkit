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

#include <virgil/iot/protocols/sdmp/fldt_private.h>
#include <virgil/iot/protocols/sdmp/sdmp_private.h>
#include <virgil/iot/macros/macros.h>

/******************************************************************************/
int
vs_fldt_send_request(const vs_netif_t *netif,
                     const vs_mac_addr_t *mac,
                     vs_sdmp_fldt_element_e element,
                     const uint8_t *data,
                     uint16_t data_sz) {

    uint8_t buffer[sizeof(vs_sdmp_packet_t) + data_sz];
    vs_sdmp_packet_t *packet;

    VS_IOT_ASSERT(data);
    VS_IOT_ASSERT(data_sz);

    VS_IOT_MEMSET(buffer, 0, sizeof(buffer));

    // Prepare pointers
    packet = (vs_sdmp_packet_t *)buffer;

    // Prepare request
    packet->header.element_id = element;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
    packet->header.service_id = VS_FLDT_SERVICE_ID;
#pragma GCC diagnostic pop
    packet->header.content_size = data_sz;
    if (data_sz) {
        VS_IOT_MEMCPY(packet->content, data, data_sz);
    }
    _sdmp_fill_header(mac, packet);

    // Send request
    return vs_sdmp_send(netif, buffer, sizeof(vs_sdmp_packet_t) + packet->header.content_size);
}
