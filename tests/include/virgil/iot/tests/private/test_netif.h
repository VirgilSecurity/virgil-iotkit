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

#ifndef VS_IOT_SDK_TESTS_SDMP_H_
#define VS_IOT_SDK_TESTS_SDMP_H_

#include <stdbool.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/logger/logger.h>

typedef union {
    uint8_t membuf;

    struct {
        unsigned initialized : 1;
        unsigned deinitialized : 1;
        unsigned mac_addr_set_up : 1;
        unsigned sent : 1;
    };
} netif_state_t;

extern netif_state_t netif_state;
extern vs_mac_addr_t mac_addr_client_call;
extern vs_mac_addr_t mac_addr_server_call;
extern bool is_client_call;

void
prepare_test_netif(vs_netif_t *netif);

#define SDMP_CHECK_GOTO(OPERATION, DESCRIPTION, ...)                                                                   \
    if ((OPERATION) != 0) {                                                                                            \
        VS_LOG_ERROR((DESCRIPTION), ##__VA_ARGS__);                                                                    \
        goto terminate;                                                                                                \
    }

#define SDMP_CHECK_ERROR_GOTO(OPERATION, DESCRIPTION, ...)                                                             \
    if ((OPERATION) == 0) {                                                                                            \
        VS_LOG_ERROR((DESCRIPTION), ##__VA_ARGS__);                                                                    \
        goto terminate;                                                                                                \
    }

#define MAC_ADDR_CHECK_GOTO(CURRENT, WAITED)                                                                           \
    if (memcmp((CURRENT).bytes, (WAITED).bytes, sizeof(vs_mac_addr_t))) {                                              \
        VS_LOG_ERROR("Current MAC address is incorrect");                                                              \
        goto terminate;                                                                                                \
    }

#define NETIF_OP_CHECK_GOTO(OPERATION)                                                                                 \
    if ((OPERATION) == 0) {                                                                                            \
        VS_LOG_ERROR("netif operation " #OPERATION " has not been called");                                            \
        goto terminate;                                                                                                \
    }

#endif // VS_IOT_SDK_TESTS_SDMP_H_
