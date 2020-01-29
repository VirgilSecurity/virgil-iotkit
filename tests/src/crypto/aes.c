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

#include <virgil/iot/tests/helpers.h>
#include <private/private_helpers.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <stdlib-config.h>
/******************************************************************************/
static bool
test_aes_cbc_cases(vs_secmodule_impl_t *secmodule_impl) {
    static const uint8_t source[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                                     0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
                                     0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
                                     0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
                                     0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    static const uint8_t encrypted_source[] = {
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
            0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
            0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
            0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
            0x3f, 0x46, 0x17, 0x96, 0xd6, 0xb0, 0xd6, 0xb2, 0xe0, 0xc2, 0xa7, 0x2b, 0x4d, 0x80, 0xe6, 0x44};
    static const uint8_t iv[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
                                  0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
                                  0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    static const uint16_t data_sz = sizeof(source);
    static const uint16_t iv_sz = sizeof(iv);
    static const uint16_t key_bitsz = sizeof(key) * 8;

    uint8_t crypted[sizeof(source) + 16 - (sizeof(source) % 16)];
    uint8_t decrypted[sizeof(source)];
    uint8_t iv_tmp[iv_sz];
    vs_status_e res;

    VS_IOT_MEMCPY(iv_tmp, iv, iv_sz);

    res = secmodule_impl->aes_encrypt(
            VS_AES_CBC, key, key_bitsz, iv_tmp, iv_sz, NULL, 0, data_sz, source, crypted, NULL, 0);

    VS_SECMODULE_CHECK_IS_NOT_IMPLEMENTED(res, "AES CBC encrypt is not implemented");

    STATUS_CHECK_RET_BOOL(res, "Unable to encrypt data");
    MEMCMP_CHECK_RET(encrypted_source, crypted, sizeof(encrypted_source), false);

    VS_IOT_MEMCPY(iv_tmp, iv, iv_sz);

    res = secmodule_impl->aes_decrypt(
            VS_AES_CBC, key, key_bitsz, iv_tmp, iv_sz, NULL, 0, sizeof(crypted), crypted, decrypted, NULL, 0);

    VS_SECMODULE_CHECK_IS_NOT_IMPLEMENTED(res, "AES CBC decrypt is not implemented");

    STATUS_CHECK_RET_BOOL(res, "Unable to decrypt");
    MEMCMP_CHECK_RET(source, decrypted, data_sz, false);

    return true;
}

/******************************************************************************/
static bool
test_aes_gcm_cases(vs_secmodule_impl_t *secmodule_impl) {
#if 0
    static const uint8_t source[] = "Input data to be crypted";
    static const uint8_t iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
    static const uint8_t add[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                                  0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
    static const uint8_t key[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
#endif
    static const uint8_t source[] = {0xDE, 0xAD, 0xBE, 0xAF};
    static const uint8_t iv[] = {0x78, 0xbe, 0xf6, 0x55, 0xdf, 0xd8, 0x99, 0x0b, 0x04, 0xd2, 0xa2, 0x56};
    static const uint8_t add[] = {
            0x9d, 0x8c, 0x67, 0x34, 0x54, 0x67, 0x97, 0xc5, 0x81, 0xb9, 0xb1, 0xd0, 0xd4, 0xf0, 0x5b, 0x27,
            0xfe, 0x05, 0x39, 0xbd, 0x01, 0x65, 0x5d, 0x2d, 0x1a, 0x8a, 0x14, 0x89, 0xcd, 0xf8, 0x04, 0x22,
            0x87, 0x53, 0xd7, 0x72, 0x72, 0xbf, 0x6d, 0xed, 0x19, 0xd4, 0x7a, 0x6a, 0xbd, 0x62, 0x81, 0xea,
            0x95, 0x91, 0xd4, 0xbc, 0xc1, 0xbe, 0x22, 0x23, 0x05, 0xfd, 0xf6, 0x89, 0xc5, 0xfa, 0xa4, 0xc1,
            0x13, 0x31, 0xcf, 0xfb, 0xf4, 0x22, 0x15, 0x46, 0x9b, 0x81, 0xf6, 0x1b, 0x40, 0x41, 0x5d, 0x81,
            0xcc, 0x37, 0x16, 0x1e, 0x5c, 0x02, 0x58, 0xa6, 0x76, 0x42, 0xb9, 0xb8, 0xac, 0x62, 0x7d, 0x6e,
            0x39, 0xf4, 0x3e, 0x48, 0x5e, 0x1f, 0xf5, 0x22, 0xac, 0x74, 0x2a, 0x07, 0xde, 0xfa, 0x35, 0x69,
            0xae, 0xb5, 0x99, 0x90, 0xcb, 0x44, 0xc4, 0xf3, 0xd9, 0x52, 0xf8, 0x11, 0x9f, 0xf1, 0x11, 0x1d,
    };
    static const uint8_t key[] = {
            0x43, 0xc9, 0xe2, 0x09, 0xda, 0x3c, 0x19, 0x71, 0xd9, 0x86, 0xa4, 0x5b, 0x92, 0xf2, 0xfa, 0x0d,
            0x2d, 0x15, 0x51, 0x83, 0x73, 0x0d, 0x21, 0xd7, 0x1e, 0xd8, 0xe2, 0x28, 0x4e, 0xc3, 0x08, 0xe3,
    };

    uint8_t crypted[sizeof(source)];
    uint8_t auth_decrypted[sizeof(source)];
    uint8_t tag[16] = {0};
    static const uint16_t data_sz = sizeof(source);
    static const uint16_t iv_sz = sizeof(iv);
    static const uint16_t add_sz = sizeof(add);
    static const uint16_t tag_sz = sizeof(tag);
    static const uint16_t key_bitsz = sizeof(key) * 8;
    vs_status_e res;

    res = secmodule_impl->aes_encrypt(
            VS_AES_GCM, key, key_bitsz, iv, iv_sz, add, add_sz, data_sz, source, crypted, tag, tag_sz);

    VS_SECMODULE_CHECK_IS_NOT_IMPLEMENTED(res, "AES GCM encrypt is not implemented");

    STATUS_CHECK_RET_BOOL(res, "Unable to encrypt data");

#if 0
    uint8_t decrypted[sizeof(source)];
    res = vs_secmodule_aes_decrypt(
                        aes_type, key, key_bitsz, iv, iv_sz, add, add_sz, data_sz, crypted, decrypted, tag, tag_sz);

    VS_SECMODULE_CHECK_IS_NOT_IMPLEMENTED(res, "AES GCM decrypt is not implemented");

    STATUS_CHECK_RET_BOOL(ret,"Unable to decrypt data");
#endif

    res = secmodule_impl->aes_auth_decrypt(
            VS_AES_GCM, key, key_bitsz, iv, iv_sz, add, add_sz, data_sz, crypted, auth_decrypted, tag, tag_sz);

    VS_SECMODULE_CHECK_IS_NOT_IMPLEMENTED(res, "AES GCM auth decrypt is not implemented");

    MEMCMP_CHECK_RET(source, auth_decrypted, data_sz, false);

    STATUS_CHECK_RET_BOOL(res, "Unable to decrypt with authentication");

    return true;
}

/******************************************************************************/
uint16_t
test_aes(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;

    START_TEST("AES tests");

    TEST_CASE_OK("GCM", test_aes_gcm_cases(secmodule_impl));
    TEST_CASE_OK("CBC", test_aes_cbc_cases(secmodule_impl));

terminate:
    return failed_test_result;
}
