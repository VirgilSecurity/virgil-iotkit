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

#include <stdint.h>

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>


#ifdef __cplusplus
extern "C" {
#endif

#define VS_SDMP_COMMAND_NOT_SUPPORTED (100)

int
vs_sdmp_init(vs_netif_t *default_netif);

int
vs_sdmp_deinit();

#if 0
int
vs_sdmp_add_netif(const vs_netif_t *netif);
#endif

const vs_netif_t *
vs_sdmp_default_netif(void);

int
vs_sdmp_send(const vs_netif_t *netif, const uint8_t *data, uint16_t data_sz);

int
vs_sdmp_register_service(const vs_sdmp_service_t *service);

int
vs_sdmp_mac_addr(const vs_netif_t *netif, vs_mac_addr_t *mac_addr);

const vs_mac_addr_t *
vs_sdmp_broadcast_mac(void);

#ifdef __cplusplus
}
#endif