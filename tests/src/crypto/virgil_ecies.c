//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include <global-hal.h>

#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/secmodule/secmodule.h>

const char *test_recipient_id = "test-recipient-id";
const char *test_data = "this string will be encrypted";

/**********************************************************/
static bool
_ecies_crypt_case(vs_secmodule_impl_t *secmodule_impl,
                  const uint8_t *recipient_id,
                  size_t recipient_id_sz,
                  const uint8_t *data,
                  size_t data_sz) {

    uint8_t encrypted_data[1024];
    size_t encrypted_data_sz;

    uint8_t decrypted_data[128];
    size_t decrypted_data_sz;

    BOOL_CHECK_RET(VS_CODE_OK != vs_secmodule_ecies_encrypt(secmodule_impl,
                                                            recipient_id,
                                                            recipient_id_sz,
                                                            (uint8_t *)data,
                                                            data_sz,
                                                            encrypted_data,
                                                            data_sz,
                                                            &encrypted_data_sz),
                   "Success call with small output buffer");

    BOOL_CHECK_RET(VS_CODE_OK == vs_secmodule_ecies_encrypt(secmodule_impl,
                                                            recipient_id,
                                                            recipient_id_sz,
                                                            (uint8_t *)data,
                                                            data_sz,
                                                            encrypted_data,
                                                            sizeof(encrypted_data),
                                                            &encrypted_data_sz),
                   "Error encrypt data");

    BOOL_CHECK_RET(VS_CODE_OK == vs_secmodule_ecies_decrypt(secmodule_impl,
                                                            recipient_id,
                                                            recipient_id_sz,
                                                            (uint8_t *)encrypted_data,
                                                            encrypted_data_sz,
                                                            decrypted_data,
                                                            sizeof(decrypted_data),
                                                            &decrypted_data_sz),
                   "Error decrypt data");

    return decrypted_data_sz == data_sz && 0 == VS_IOT_MEMCMP(data, decrypted_data, decrypted_data_sz);
}

/**********************************************************/
uint16_t
vs_virgil_ecies_test(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;
    START_TEST("Virgil ecies encryption");

    TEST_CASE_OK("Prepare keystorage",
                 vs_test_erase_otp_provision(secmodule_impl) && vs_test_create_device_key(secmodule_impl));
    TEST_CASE_OK("Encrypt/decrypt data",
                 _ecies_crypt_case(secmodule_impl,
                                   (uint8_t *)test_recipient_id,
                                   VS_IOT_STRLEN(test_recipient_id),
                                   (uint8_t *)test_data,
                                   VS_IOT_STRLEN(test_data) + 1));

terminate:

    return failed_test_result;
}