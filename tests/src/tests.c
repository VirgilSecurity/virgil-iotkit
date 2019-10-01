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

#include <stdlib.h>
#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/tests/private/test_hl_keys_data.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>

uint16_t
sdmp_tests(void);
uint16_t
prvs_tests(void);
uint16_t
fldt_tests(void);

uint16_t
test_hash(void);
uint16_t
test_hmac(void);
uint16_t
test_kdf2(void);
uint16_t
test_ecdsa(void);
uint16_t
test_ecdh(void);
uint16_t
test_keypair(void);
uint16_t
test_random(void);
uint16_t
test_aes(void);
uint16_t
test_sign_converters(void);
uint16_t
test_pubkeys_converters(void);
uint16_t
test_keystorage_and_tl(void);
uint16_t
vs_virgil_ecies_test();

/******************************************************************************/
static bool
_save_hl_key(size_t slot, const char *id_str, const uint8_t *in_data, uint16_t data_sz) {

    VS_HSM_CHECK_RET(vs_hsm_slot_save(slot, in_data, data_sz), "Unable to save data to slot = %d (%s)", slot, id_str);

    return true;
}

/**********************************************************/
bool
vs_test_erase_otp_provision() {
    VS_HEADER_SUBCASE("Erase otp slots");
    if (VS_HSM_ERR_OK != vs_hsm_slot_delete(PRIVATE_KEY_SLOT) || VS_HSM_ERR_OK != vs_hsm_slot_delete(REC1_KEY_SLOT) ||
        VS_HSM_ERR_OK != vs_hsm_slot_delete(REC2_KEY_SLOT)) {
        VS_LOG_ERROR("[AP] Error. Can't erase OTP slots. ");
        return false;
    }
    return true;
}

/**********************************************************/
bool
vs_test_create_device_key() {
    VS_HEADER_SUBCASE("Create device keypair");
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_keypair_create(PRIVATE_KEY_SLOT, VS_KEYPAIR_EC_SECP256R1),
                   "Error create device key");
    return true;
}

/**********************************************************/
bool
vs_test_save_hl_keys() {
    bool res = true;
    res &= _save_hl_key(REC1_KEY_SLOT, "PBR1", recovery1_pub, recovery1_pub_len);
    res &= _save_hl_key(REC2_KEY_SLOT, "PBR2", recovery2_pub, recovery2_pub_len);

    res &= _save_hl_key(AUTH1_KEY_SLOT, "PBA1", auth1_pub, auth1_pub_len);
    res &= _save_hl_key(AUTH2_KEY_SLOT, "PBA2", auth2_pub, auth2_pub_len);

    res &= _save_hl_key(FW1_KEY_SLOT, "PBF1", firmware1_pub, firmware1_pub_len);
    res &= _save_hl_key(FW2_KEY_SLOT, "PBF2", firmware2_pub, firmware2_pub_len);

    res &= _save_hl_key(TL1_KEY_SLOT, "PBT1", tl_service1_pub, tl_service1_pub_len);
    res &= _save_hl_key(TL2_KEY_SLOT, "PBT2", tl_service2_pub, tl_service2_pub_len);

    return res;
}

/**********************************************************/
static uint16_t
crypto_tests(void) {
    uint16_t failed_test_result = 0;

    failed_test_result = test_hash();
    failed_test_result += test_hmac();
    failed_test_result += test_kdf2();
    failed_test_result += test_random();
    failed_test_result += test_aes();
    failed_test_result += test_keystorage_and_tl();
    failed_test_result += test_keypair();
    failed_test_result += test_ecdsa();
    failed_test_result += test_ecdh();
    failed_test_result += vs_virgil_ecies_test();
#if !VIRGIL_IOT_MCU_BUILD
    failed_test_result += test_sign_converters();
    failed_test_result += test_pubkeys_converters();
#endif
    return failed_test_result;
}

/**********************************************************/
uint16_t
vs_tests_checks(bool print_start_finish_tests) {
    uint16_t failed_test_result = 0;

    if (print_start_finish_tests) {
        START_TESTS;
    }

    failed_test_result = sdmp_tests();
    failed_test_result += prvs_tests();
    failed_test_result += fldt_tests();

    failed_test_result += crypto_tests();

    if (print_start_finish_tests) {
        FINISH_TESTS;
    }

    return failed_test_result;
}
