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

#include <stdbool.h>
#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/tests/private/test_netif.h>
#include <virgil/iot/tests/private/test_fwdt.h>
#include <virgil/iot/protocols/sdmp/FWDT.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/tests/private/test_fwdt.h>
#include <stdlib-config.h>
#include <virgil/iot/hsm/hsm_structs.h>

static vs_netif_t test_netif;
static vs_sdmp_fwdt_dnid_list_t dnid_list;
static const uint32_t wait_msec = 0;

static const vs_mac_addr_t mac_addr_server = {.bytes = {0xF2, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6}};
//static const vs_mac_addr_t mac_addr_fake_server = {.bytes = {0xE2, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6}};
static const vs_mac_addr_t mac_addr_client = {.bytes = {0x12, 0x12, 0x13, 0x14, 0x15, 0x16}};

/**********************************************************/
static bool
test_fwdt_register(void) {

    SDMP_CHECK_GOTO(vs_sdmp_register_service(vs_sdmp_fwdt_service()), "vs_sdmp_init call");

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_configure_hal(void) {

    SDMP_CHECK_GOTO(vs_sdmp_fwdt_configure_hal(make_fwdt_implementation()), "vs_sdmp_fwdt_configure_hal call");

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_uninitialized_devices(void) {

    fwdt_call.call = 0;
    is_client_call = true;

    SDMP_CHECK_GOTO(vs_sdmp_fwdt_uninitialized_devices(&test_netif, &dnid_list, wait_msec),
                    "vs_sdmp_fwdt_uninitialized_devices call");

    FWDT_OP_CHECK_GOTO(fwdt_call.dnid);
    CHECK_GOTO(dnid_list.count == 1, "Incorrect dnid list size %lu while it must be equal to %d", dnid_list.count, 1);
    MAC_ADDR_CHECK_GOTO(dnid_list.elements[0].mac_addr, mac_addr_server);

    return true;

    terminate:

    return false;
}

/**********************************************************/
void
fwdt_tests(void) {

    START_TEST("FWDT");

    prepare_test_netif(&test_netif);

    SDMP_CHECK_GOTO(vs_sdmp_init(&test_netif), "vs_sdmp_init call");

    mac_addr_server_call = mac_addr_server;
    mac_addr_client_call = mac_addr_client;

    TEST_CASE_OK("register FWDT service", test_fwdt_register());
    TEST_CASE_OK("configure FWDT HAL", test_configure_hal());
    TEST_CASE_OK("set uninitialized devices", test_uninitialized_devices());

    SDMP_CHECK_GOTO(vs_sdmp_deinit(&test_netif), "vs_sdmp_deinit call");

terminate:;
}
