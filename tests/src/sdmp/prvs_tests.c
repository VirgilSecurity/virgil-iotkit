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
#include <helpers.h>
#include <test_netif.h>
#include <test_prvs.h>
#include <virgil/iot/protocols/sdmp/PRVS.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp.h>
#include <private/test_prvs.h>
#include <stdlib-config.h>

static vs_netif_t test_netif;
static vs_sdmp_prvs_dnid_list_t dnid_list;
static const size_t wait_msec = 0;

static const vs_mac_addr_t mac_addr_server = {.bytes = {0xF2, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6}};
static const vs_mac_addr_t mac_addr_fake_server = {.bytes = {0xE2, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6}};
static const vs_mac_addr_t mac_addr_client = {.bytes = {0x12, 0x12, 0x13, 0x14, 0x15, 0x16}};

/**********************************************************/
static bool
test_prvs_register(void) {

    SDMP_CHECK_GOTO(vs_sdmp_register_service(vs_sdmp_prvs_service()), "vs_sdmp_init call");

    return true;

    terminate:

    return false;
}

/**********************************************************/
static bool
test_configure_hal(void) {

    SDMP_CHECK_GOTO(vs_sdmp_prvs_configure_hal(make_prvs_implementation()), "vs_sdmp_prvs_configure_hal call");

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_uninitialized_devices(void) {

    prvs_call.call = 0;
    is_client_call = true;

    SDMP_CHECK_GOTO(vs_sdmp_prvs_uninitialized_devices(&test_netif, &dnid_list, wait_msec),
                    "vs_sdmp_prvs_uninitialized_devices call");

    PRVS_OP_CHECK_GOTO(prvs_call.dnid);
    BOOL_CHECK_GOTO(
            dnid_list.count == 1, "Incorrect dnid list size %d while it must be equal to %d", dnid_list.count, 1);
    MAC_ADDR_CHECK_GOTO(dnid_list.elements[0].mac_addr, mac_addr_server);

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_save_provision(void) {
    vs_sdmp_pubkey_t res_pubkey;
    static const vs_sdmp_pubkey_t asav_response = {.pubkey = "Password", .pubkey_sz = 9};

    prvs_call.call = 0;
    is_client_call = true;

    make_server_response.finalize_storage.asav_response = asav_response;

    SDMP_CHECK_GOTO(vs_sdmp_prvs_save_provision(&test_netif, &mac_addr_server, &res_pubkey, wait_msec),
                    "vs_sdmp_prvs_save_provision call");
    PRVS_OP_CHECK_GOTO(prvs_call.finalize_storage);
    BOOL_CHECK_GOTO(res_pubkey.pubkey_sz == asav_response.pubkey_sz &&
                            !VS_IOT_MEMCMP(res_pubkey.pubkey, asav_response.pubkey, res_pubkey.pubkey_sz),
                    "Incorrect received public key");

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_device_info(void) {
    uint8_t response_buf[256];
    vs_sdmp_prvs_devi_t *dev_resp = (vs_sdmp_prvs_devi_t *)response_buf;
    uint8_t server_buf[256];
    vs_sdmp_prvs_devi_t *serv_resp = (vs_sdmp_prvs_devi_t *)server_buf;
    static const uint8_t pubkey_raw[] = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    size_t pos;

    prvs_call.call = 0;
    is_client_call = true;

    for (pos = 0; pos < sizeof(response_buf); ++pos) {
        server_buf[pos] = pos;
    }

    serv_resp->mac = mac_addr_client;
    VS_IOT_MEMCPY((char *)serv_resp->own_key.pubkey, pubkey_raw, sizeof(pubkey_raw));

    make_server_response.device_info = serv_resp;

    serv_resp->own_key.pubkey_sz = 255;
    serv_resp->signature.val_sz = 255;

    SDMP_CHECK_ERROR_GOTO(vs_sdmp_prvs_device_info(&test_netif, &mac_addr_server, dev_resp, sizeof(response_buf), wait_msec),
                    "vs_sdmp_prvs_device_info call");

    serv_resp->own_key.pubkey_sz = sizeof(pubkey_raw);
    serv_resp->signature.val_sz = sizeof(response_buf) - sizeof(vs_sdmp_prvs_devi_t);

    SDMP_CHECK_GOTO(vs_sdmp_prvs_device_info(&test_netif, &mac_addr_server, dev_resp, sizeof(response_buf), wait_msec),
                    "vs_sdmp_prvs_device_info call");

    PRVS_OP_CHECK_GOTO(prvs_call.device_info);

    BOOL_CHECK_GOTO(sizeof(response_buf) != server_request.finalize_storage.buf_sz,
                    "Incorrect request received by server");

    BOOL_CHECK_GOTO(
            dev_resp->own_key.pubkey_sz == serv_resp->own_key.pubkey_sz &&
                    !VS_IOT_MEMCMP(dev_resp->own_key.pubkey, serv_resp->own_key.pubkey, dev_resp->own_key.pubkey_sz),
            "Incorrect own_key");
    BOOL_CHECK_GOTO(
            dev_resp->signature.val_sz == serv_resp->signature.val_sz &&
                    !VS_IOT_MEMCMP(dev_resp->signature.val, serv_resp->signature.val, dev_resp->signature.val_sz),
            "Incorrect signature");
    BOOL_CHECK_GOTO(!VS_IOT_MEMCMP(dev_resp->mac.bytes, serv_resp->mac.bytes, sizeof(serv_resp->mac.bytes)),
                    "Incorrect MAC address");
    BOOL_CHECK_GOTO(dev_resp->manufacturer == serv_resp->manufacturer && dev_resp->model == serv_resp->model &&
                            dev_resp->signature.id == serv_resp->signature.id,
                    "Incorrect response");

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_sign_data(void) {
    static const uint8_t data[] = {"Some data to be signed"};
    static uint8_t serv_sign[] = {"Signature example"};
    uint8_t signature[128];
    size_t signature_sz = sizeof(signature);
    bool res = false;

    prvs_call.call = 0;
    is_client_call = true;

    server_request.sign_data.data = NULL;

    make_server_response.sign_data.signature = serv_sign;
    make_server_response.sign_data.signature_sz = sizeof(serv_sign);

    SDMP_CHECK_GOTO(vs_sdmp_prvs_sign_data(&test_netif,
                                           &mac_addr_server,
                                           data,
                                           sizeof(data),
                                           signature,
                                           signature_sz,
                                           &signature_sz,
                                           wait_msec),
                    "vs_sdmp_prvs_sign_data call");
    PRVS_OP_CHECK_GOTO(prvs_call.sign_data);

    BOOL_CHECK_GOTO(server_request.sign_data.data_sz == sizeof(data) &&
                            server_request.sign_data.buf_sz >= sizeof(signature) &&
                            !VS_IOT_MEMCMP(data, server_request.sign_data.data, sizeof(data)),
                    "Incorrect request received by server");

    BOOL_CHECK_GOTO(signature_sz == make_server_response.sign_data.signature_sz &&
                            !VS_IOT_MEMCMP(signature,
                                           make_server_response.sign_data.signature,
                                           make_server_response.sign_data.signature_sz),
                    "Incorrect response");

    res = true;

terminate:

    VS_IOT_FREE(server_request.sign_data.data);

    return res;
}

/**********************************************************/
static bool
test_set(bool use_fake_mac_addr) {
    static const vs_sdmp_prvs_element_t elem = VS_PRVS_PBR1;
    static const uint8_t data[] = "Some data";
    size_t data_sz;
    bool result = false;

    prvs_call.call = 0;
    is_client_call = true;
    server_request.save_data.data = NULL;

    data_sz = sizeof(data);

    if(!use_fake_mac_addr) {
        SDMP_CHECK_GOTO(vs_sdmp_prvs_set(&test_netif, &mac_addr_server, elem, data, data_sz, wait_msec),
                        "vs_sdmp_prvs_set call");
        PRVS_OP_CHECK_GOTO(prvs_call.save_data);
        BOOL_CHECK_GOTO(server_request.save_data.element_id == elem && server_request.save_data.data_sz == data_sz &&
                                !VS_IOT_MEMCMP(data, server_request.save_data.data, data_sz),
                        "Incorrect set request data");
    } else {
        SDMP_CHECK_ERROR_GOTO(vs_sdmp_prvs_set(&test_netif, &mac_addr_fake_server, elem, data, data_sz, wait_msec),
                        "vs_sdmp_prvs_set call");
    }

    result = true;

    terminate:

    VS_IOT_FREE(server_request.save_data.data);

    return result;
}

/**********************************************************/
static bool
test_finalize(void) {
    static const uint8_t data[] = {"Some data to be signed"};
    bool result = false;

    prvs_call.call = 0;
    is_client_call = true;
    server_request.finalize_tl.data = NULL;

    SDMP_CHECK_GOTO(vs_sdmp_prvs_finalize_tl(&test_netif, &mac_addr_server, data, sizeof(data), wait_msec),
                    "vs_sdmp_prvs_finalize_tl call");
    PRVS_OP_CHECK_GOTO(prvs_call.finalize_tl);
    BOOL_CHECK_GOTO(server_request.finalize_tl.data_sz == sizeof(data) &&
                            !VS_IOT_MEMCMP(data, server_request.finalize_tl.data, sizeof(data)),
                    "Incorrect request data");

    result = true;

terminate:

    VS_IOT_FREE(server_request.finalize_tl.data);

    return result;
}

/**********************************************************/
void
prvs_tests(void) {

    START_TEST("PRVS");

    prepare_test_netif(&test_netif);

    SDMP_CHECK_GOTO(vs_sdmp_init(&test_netif), "vs_sdmp_init call");

    mac_addr_server_call = mac_addr_server;
    mac_addr_client_call = mac_addr_client;

    TEST_CASE_OK("register PRVS service", test_prvs_register());
    TEST_CASE_OK("configure PRVS HAL", test_configure_hal());
    TEST_CASE_OK("set uninitialized devices", test_uninitialized_devices());
    TEST_CASE_OK("save provision", test_save_provision());
    TEST_CASE_OK("device information", test_device_info());
    TEST_CASE_OK("sign data", test_sign_data());
    TEST_CASE_OK("set data", test_set(false));
    TEST_CASE_OK("incorrect mac address", test_set(true));
    TEST_CASE_OK("finalize", test_finalize());

    SDMP_CHECK_GOTO(vs_sdmp_deinit(&test_netif), "vs_sdmp_deinit call");

terminate:;
}
