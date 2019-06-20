/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file asn1-converters.h
 * @brief Conversion between virgil asn1 structures and plain data for atecc508a
 */

#ifndef asn1_converters_h
#define asn1_converters_h

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define VIRGIL_PUBLIC_KEY_MAX_SIZE 100
#define VIRGIL_SIGNATURE_MAX_SIZE 128

#ifdef __cplusplus
extern "C" {
#endif

bool
tiny_nist256_sign_to_virgil(uint8_t sign[64], uint8_t *virgil_sign, size_t *virgil_sign_sz);

bool
tiny_nist256_pubkey_to_virgil(uint8_t public_key[64], uint8_t *virgil_public_key, size_t *virgil_public_key_sz);

bool
virgil_sign_to_mbedtls(const uint8_t *virgil_sign, size_t virgil_sign_sz, const uint8_t **sign, size_t *sign_sz);

bool
mbedtls_sign_to_virgil(uint8_t hash_type,
                       uint8_t *mbedtls_sign,
                       size_t mbedtls_sign_sz,
                       uint8_t *virgil_sign,
                       size_t buf_sz,
                       uint16_t *virgil_sign_sz);

bool
virgil_cryptogram_create_mbedtls(const uint8_t *recipient_id,
                                 size_t recipient_id_sz,
                                 const uint8_t *encrypted_key,
                                 size_t encrypted_key_sz,
                                 const uint8_t *encrypted_data,
                                 size_t encrypted_data_sz,
                                 const uint8_t iv_data[16],
                                 uint8_t *cryptogram,
                                 size_t buf_sz,
                                 size_t *cryptogram_sz);

bool
low_level_cryptogram_create_mbedtls(const uint8_t *public_key,
                                    size_t public_key_sz,
                                    const uint8_t *encrypted_data,
                                    size_t encrypted_data_sz,
                                    const uint8_t hmac[32],
                                    const uint8_t iv_data[16],
                                    uint8_t *cryptogram,
                                    size_t buf_sz,
                                    size_t *cryptogram_sz);

bool
virgil_cryptogram_parse_mbedtls(const uint8_t *virgil_encrypted_data,
                                size_t virgil_encrypted_data_sz,
                                const uint8_t *recipient_id,
                                size_t recipient_id_sz,
                                uint8_t **iv,
                                uint8_t **encrypted_key,
                                size_t *encrypted_key_sz,
                                uint8_t **encrypted_data,
                                size_t *encrypted_data_sz);

bool
mbedtls_cryptogram_parse_low_level(const uint8_t *cryptogram,
                                   size_t cryptogram_sz,
                                   uint8_t **public_key,
                                   uint8_t **iv,
                                   uint8_t **hmac,
                                   uint8_t **encrypted_data,
                                   size_t *encrypted_data_sz);

#ifdef __cplusplus
}
#endif

#endif /* asn1_converters_h */
