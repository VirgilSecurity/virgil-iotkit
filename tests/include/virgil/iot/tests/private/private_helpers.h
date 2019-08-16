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

#ifndef VS_TESTS_PRIVATE_HELPERS_H
#define VS_TESTS_PRIVATE_HELPERS_H

#include <virgil/iot/hsm/hsm_structs.h>

const char *
vs_iot_hsm_slot_descr(vs_iot_hsm_slot_e slot);

#define TEST_NOT_IMPLEMENTED(OPERATION)                                                                                \
    do {                                                                                                               \
        vs_log_level_t prev_loglev;                                                                                    \
        prev_loglev = vs_logger_get_loglev();                                                                          \
        vs_logger_set_loglev(VS_LOGLEV_CRITICAL);                                                                      \
        not_implemented = (OPERATION) == VS_HSM_ERR_NOT_IMPLEMENTED;                                                   \
        vs_logger_set_loglev(prev_loglev);                                                                             \
    } while (0)

#define TEST_KEYPAIR_NOT_IMPLEMENTED(SLOT, KEYPAIR_TYPE)                                                               \
    do {                                                                                                               \
        TEST_NOT_IMPLEMENTED(vs_hsm_keypair_create((SLOT), (KEYPAIR_TYPE)));                                           \
    } while (0)

#define TEST_HASH_NOT_IMPLEMENTED(HASH)                                                                                \
    do {                                                                                                               \
        static const uint8_t test_data[] = "Stub";                                                                     \
        uint8_t result_buf[128];                                                                                       \
        uint16_t tmp_size;                                                                                             \
        TEST_NOT_IMPLEMENTED(vs_hsm_hash_create(                                                                       \
                (HASH), (const uint8_t *)test_data, sizeof(test_data), result_buf, sizeof(result_buf), &tmp_size));    \
    } while (0)

#define TEST_ECDH_NOT_IMPLEMENTED(SLOT, KEYPAIR_TYPE)                                                                  \
    do {                                                                                                               \
        uint8_t pubkey[256] = {0};                                                                                     \
        uint16_t pubkey_sz = 0;                                                                                        \
        uint8_t shared_secret_1[128] = {0};                                                                            \
        uint16_t shared_secret_sz_1 = 0;                                                                               \
        TEST_NOT_IMPLEMENTED(vs_hsm_ecdh((SLOT),                                                                       \
                                         (KEYPAIR_TYPE),                                                               \
                                         pubkey,                                                                       \
                                         pubkey_sz,                                                                    \
                                         shared_secret_1,                                                              \
                                         sizeof(shared_secret_1),                                                      \
                                         &shared_secret_sz_1));                                                        \
    } while (0)

#define TEST_HMAC_NOT_IMPLEMENTED(HASH)                                                                                \
    do {                                                                                                               \
        static uint8_t key_raw[] = "Stub";                                                                             \
        static uint8_t input_raw[] = "Stub";                                                                           \
        uint8_t buf[128];                                                                                              \
        uint16_t tmp_sz;                                                                                               \
        TEST_NOT_IMPLEMENTED(vs_hsm_hmac(                                                                              \
                (HASH), key_raw, sizeof(key_raw), input_raw, sizeof(input_raw), buf, sizeof(buf), &tmp_sz));           \
    } while (0)

#define TEST_HKDF_NOT_IMPLEMENTED(HASH)                                                                                \
    do {                                                                                                               \
        static uint8_t salt_raw[] = "Stub";                                                                            \
        static uint8_t input_raw[] = "Stub";                                                                           \
        static uint8_t hkdf_info_raw[] = "Stub";                                                                       \
        uint8_t buf[64];                                                                                               \
        TEST_NOT_IMPLEMENTED(vs_hsm_hkdf((HASH),                                                                       \
                                         input_raw,                                                                    \
                                         sizeof(input_raw),                                                            \
                                         salt_raw,                                                                     \
                                         sizeof(salt_raw),                                                             \
                                         hkdf_info_raw,                                                                \
                                         sizeof(hkdf_info),                                                            \
                                         buf,                                                                          \
                                         sizeof(buf)));                                                                \
    } while (0)

#define TEST_KDF_NOT_IMPLEMENTED(HASH)                                                                                 \
    do {                                                                                                               \
        static uint8_t input_raw[] = "Stub";                                                                           \
        uint8_t buf[64];                                                                                               \
        TEST_NOT_IMPLEMENTED(vs_hsm_kdf(VS_KDF_2, (HASH), input_raw, sizeof(input_raw), buf, sizeof(buf)));            \
    } while (0)

#endif // VS_TESTS_PRIVATE_HELPERS_H
