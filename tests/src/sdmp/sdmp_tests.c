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

#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/tests/private/test_netif.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp.h>

static vs_netif_t test_netif;

/**********************************************************/
static bool
test_sdmp_init_deinit(void) {

    netif_state.membuf = 0;

    SDMP_CHECK_GOTO(vs_sdmp_init(&test_netif), "vs_sdmp_init call");
    NETIF_OP_CHECK_GOTO(netif_state.initialized);

    SDMP_CHECK_GOTO(vs_sdmp_deinit(&test_netif), "vs_sdmp_deinit call");
    NETIF_OP_CHECK_GOTO(netif_state.deinitialized);

    SDMP_CHECK_GOTO(vs_sdmp_init(&test_netif), "vs_sdmp_init call");
    NETIF_OP_CHECK_GOTO(netif_state.initialized);

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_sdmp_send(void) {
    const uint16_t data_sz = sizeof(vs_sdmp_packet_t);
    uint8_t data[data_sz];

    memset(data, 0, data_sz);
    netif_state.membuf = 0;

    netif_state.sent = 0;
    vs_sdmp_send(NULL, data, data_sz);
    NETIF_OP_CHECK_GOTO(netif_state.sent);

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_sdmp_mac_addr(void) {

    vs_mac_addr_t mac_addr;
    netif_state.membuf = 0;

    SDMP_CHECK_GOTO(vs_sdmp_mac_addr(0, &mac_addr), "vs_sdmp_mac_addr call");
    NETIF_OP_CHECK_GOTO(netif_state.mac_addr_set_up);

    return true;

terminate:

    return false;
}

/**********************************************************/
uint16_t
sdmp_tests(void) {
    uint16_t failed_test_result = 0;

    START_TEST("SDMP");

    prepare_test_netif(&test_netif);

    TEST_CASE_OK("Initialization / deinitialization", test_sdmp_init_deinit());
    TEST_CASE_OK("Send", test_sdmp_send());
    TEST_CASE_OK("Mac address", test_sdmp_mac_addr());

    SDMP_CHECK_GOTO(vs_sdmp_deinit(&test_netif), "vs_sdmp_deinit call");

    // Call for possible crashes and memory leaks
    SDMP_CHECK_GOTO(vs_sdmp_send(NULL, NULL, 0), "vs_sdmp_send call");

terminate:;
    return failed_test_result;
}
