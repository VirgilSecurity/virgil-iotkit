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
#include <virgil/iot/tests/private/test_prvs.h>
#include <virgil/iot/protocols/sdmp/prvs.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/tests/private/test_prvs.h>
#include <stdlib-config.h>
#include <virgil/iot/hsm/hsm_structs.h>
#include <global-hal.h>

static vs_netif_t test_netif;
static vs_sdmp_prvs_dnid_list_t dnid_list;
static const uint32_t wait_msec = 0;

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
    CHECK_GOTO(dnid_list.count == 1, "Incorrect dnid list size %lu while it must be equal to %d", dnid_list.count, 1);
    MAC_ADDR_CHECK_GOTO(dnid_list.elements[0].mac_addr, mac_addr_server);

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_save_provision(void) {
    uint8_t res_buf[256];
    vs_pubkey_t *res_pubkey = (vs_pubkey_t *)res_buf;

    vs_pubkey_t *asav_response = &make_server_response.finalize_storage.asav_response;
    prvs_call.call = 0;
    is_client_call = true;

    memcpy(asav_response->pubkey, "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 48);
    asav_response->key_type = VS_KEY_IOT_DEVICE;
    asav_response->ec_type = VS_KEYPAIR_EC_SECP192K1;

    make_server_response.finalize_storage.size = strlen((char *)asav_response->pubkey) + sizeof(vs_pubkey_t);

    SDMP_CHECK_GOTO(vs_sdmp_prvs_save_provision(&test_netif, &mac_addr_server, res_buf, sizeof(res_buf), wait_msec),
                    "vs_sdmp_prvs_save_provision call");
    PRVS_OP_CHECK_GOTO(prvs_call.finalize_storage);

    CHECK_GOTO(res_pubkey->key_type == asav_response->key_type && res_pubkey->ec_type == asav_response->ec_type &&
                       !VS_IOT_MEMCMP(res_pubkey->pubkey, asav_response->pubkey, 48),
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
    vs_pubkey_t *serv_pubkey = (vs_pubkey_t *)serv_resp->data;
    vs_sign_t *serv_sign;
    static const uint8_t pubkey_raw[] = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    static const uint8_t sign_raw[] = {20, 19, 18, 17, 16, 15, 14, 13, 12, 11};
    uint16_t pos;
    uint16_t size;

    const uint8_t *buf1;
    const uint8_t *buf2;

    prvs_call.call = 0;
    is_client_call = true;

    for (pos = 0; pos < sizeof(response_buf); ++pos) {
        server_buf[pos] = pos;
    }

    memcpy(&serv_resp->mac, &mac_addr_client, sizeof(vs_mac_addr_t));
    serv_pubkey->ec_type = 255;
    serv_pubkey->key_type = 255;
    VS_IOT_MEMCPY((char *)serv_pubkey->pubkey, pubkey_raw, sizeof(pubkey_raw));

    serv_sign = (vs_sign_t *)(serv_resp->data + sizeof(pubkey_raw) + sizeof(vs_pubkey_t));
    serv_sign->ec_type = 255;
    serv_sign->hash_type = 255;
    serv_sign->signer_type = 255;
    VS_IOT_MEMCPY((char *)serv_sign->raw_sign_pubkey, sign_raw, sizeof(sign_raw));

    make_server_response.device_info = serv_resp;

    serv_resp->data_sz = sizeof(pubkey_raw) + sizeof(vs_pubkey_t) + sizeof(sign_raw) + sizeof(vs_sign_t);

    SDMP_CHECK_GOTO(vs_sdmp_prvs_device_info(&test_netif, &mac_addr_server, dev_resp, sizeof(response_buf), wait_msec),
                    "vs_sdmp_prvs_device_info call");

    PRVS_OP_CHECK_GOTO(prvs_call.device_info);

    CHECK_GOTO(sizeof(response_buf) != server_request.finalize_storage.buf_sz, "Incorrect request received by server");

    buf1 = dev_resp->data;
    buf2 = serv_resp->data;
    size = dev_resp->data_sz;
    CHECK_GOTO(dev_resp->data_sz == serv_resp->data_sz && !VS_IOT_MEMCMP(buf1, buf2, size), "Incorrect own_key");

    CHECK_GOTO(!VS_IOT_MEMCMP(dev_resp->mac.bytes, serv_resp->mac.bytes, sizeof(serv_resp->mac.bytes)),
               "Incorrect MAC address");
    MEMCMP_CHECK(dev_resp->manufacturer, serv_resp->manufacturer, sizeof(dev_resp->manufacturer));
    CHECK_GOTO(dev_resp->model == serv_resp->model, "Incorrect response");

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
    uint16_t signature_sz = sizeof(signature);
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

    CHECK_GOTO(server_request.sign_data.data_sz == sizeof(data) &&
                       server_request.sign_data.buf_sz >= sizeof(signature) &&
                       !VS_IOT_MEMCMP(data, server_request.sign_data.data, sizeof(data)),
               "Incorrect request received by server");

    CHECK_GOTO(signature_sz == make_server_response.sign_data.signature_sz &&
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
    static const vs_sdmp_prvs_element_e elem = VS_PRVS_PBR1;
    static const uint8_t data[] = "Some data";
    uint16_t data_sz;
    bool result = false;

    prvs_call.call = 0;
    is_client_call = true;
    server_request.save_data.data = NULL;

    data_sz = sizeof(data);

    if (!use_fake_mac_addr) {
        SDMP_CHECK_GOTO(vs_sdmp_prvs_set(&test_netif, &mac_addr_server, elem, data, data_sz, wait_msec),
                        "vs_sdmp_prvs_set call");
        PRVS_OP_CHECK_GOTO(prvs_call.save_data);
        CHECK_GOTO(server_request.save_data.element_id == elem && server_request.save_data.data_sz == data_sz &&
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

    SDMP_CHECK_GOTO(vs_sdmp_prvs_set_tl_footer(&test_netif, &mac_addr_server, data, sizeof(data), wait_msec),
                    "vs_sdmp_prvs_set_tl_footer call");
    PRVS_OP_CHECK_GOTO(prvs_call.finalize_tl);
    CHECK_GOTO(server_request.finalize_tl.data_sz == sizeof(data) &&
                       !VS_IOT_MEMCMP(data, server_request.finalize_tl.data, sizeof(data)),
               "Incorrect request data");

    result = true;

terminate:

    VS_IOT_FREE(server_request.finalize_tl.data);

    return result;
}

/**********************************************************/
uint16_t
prvs_tests(void) {
    uint16_t failed_test_result = 0;

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

terminate:
    return failed_test_result;
}
