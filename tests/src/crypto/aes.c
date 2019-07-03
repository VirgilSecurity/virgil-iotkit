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
#include <virgil/iot/hsm/hsm_interface.h>
#include <stdlib-config.h>

/******************************************************************************/
static bool
test_aes_cases(vs_iot_aes_type_e aes_type) {
    static const uint8_t source[] = "Input data to be crypted";
    uint8_t crypted[sizeof(source)];
    uint8_t decrypted[sizeof(source)];
    uint8_t auth_decrypted[sizeof(source)];
    static const uint8_t iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
    static const uint8_t add[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                                  0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
    uint8_t tag[16] = {0};
    static const uint8_t key[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    static const uint16_t data_sz = sizeof(source);
    static const uint16_t iv_sz = sizeof(iv);
    static const uint16_t add_sz = sizeof(add);
    static const uint16_t tag_sz = sizeof(tag);
    static const uint16_t key_bitsz = sizeof(key) * 8;

    VS_HSM_CHECK_RET(
            vs_hsm_aes_encrypt(aes_type, key, key_bitsz, iv, iv_sz, add, add_sz, data_sz, source, crypted, tag, tag_sz),
            "Unable to encrypt data");
    VS_HSM_CHECK_RET(
            vs_hsm_aes_decrypt(
                    aes_type, key, key_bitsz, iv, iv_sz, add, add_sz, data_sz, crypted, decrypted, tag, tag_sz),
            "Unable to decrypt data");
    MEMCMP_CHECK_RET(source, decrypted, data_sz);
    VS_HSM_CHECK_RET(
            vs_hsm_aes_auth_decrypt(
                    aes_type, key, key_bitsz, iv, iv_sz, add, add_sz, data_sz, crypted, auth_decrypted, tag, tag_sz),
            "Unable to decrypt with authentication");
    MEMCMP_CHECK_RET(source, auth_decrypted, data_sz);

    return true;
}

/******************************************************************************/
void
test_aes(void) {

    START_TEST("AES tests");

    TEST_CASE_OK("GCM", test_aes_cases(VS_AES_GCM));

terminate:;
}
