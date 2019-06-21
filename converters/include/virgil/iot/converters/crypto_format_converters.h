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

#ifndef VS_CRYPTO_CONVERTERS_H
#define VS_CRYPTO_CONVERTERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <virgil/iot/hsm/hsm_structs.h>

#ifdef __cplusplus
extern "C" {
#endif

bool
vs_converters_pubkey_to_raw(vs_hsm_keypair_type_e keypair_type,
                            const uint8_t *public_key,
                            uint16_t public_key_sz,
                            uint8_t *pubkey_raw,
                            uint16_t buf_sz,
                            uint16_t *pubkey_raw_sz);
bool
vs_converters_pubkey_to_virgil(vs_hsm_keypair_type_e keypair_type,
                               const uint8_t *public_key_in,
                               uint16_t public_key_in_sz,
                               uint8_t *public_key_out,
                               uint16_t buf_sz,
                               uint16_t *public_key_out_sz);
bool
vs_converters_virgil_sign_to_raw(vs_hsm_keypair_type_e keypair_type,
                                 const uint8_t *virgil_sign,
                                 size_t virgil_sign_sz,
                                 uint8_t *sign,
                                 uint16_t buf_sz,
                                 uint16_t *sign_sz);

bool
vs_converters_raw_sign_to_virgil(vs_hsm_keypair_type_e keypair_type,
                                 vs_hsm_hash_type_e hash_type,
                                 const uint8_t *raw_sign,
                                 size_t raw_sign_sz,
                                 uint8_t *virgil_sign,
                                 size_t buf_sz,
                                 uint16_t *virgil_sign_sz);

bool
vs_converters_virgil_cryptogram_create_mbedtls(const uint8_t *recipient_id,
                                               size_t recipient_id_sz,
                                               const uint8_t *encrypted_key,
                                               size_t encrypted_key_sz,
                                               const uint8_t *encrypted_data,
                                               size_t encrypted_data_sz,
                                               const uint8_t *iv_data,
                                               uint8_t *cryptogram,
                                               size_t buf_sz,
                                               size_t *cryptogram_sz);

bool
vs_converters_low_level_cryptogram_create_mbedtls(const uint8_t *public_key,
                                                  size_t public_key_sz,
                                                  const uint8_t *encrypted_data,
                                                  size_t encrypted_data_sz,
                                                  const uint8_t *hmac,
                                                  const uint8_t *iv_data,
                                                  uint8_t *cryptogram,
                                                  size_t buf_sz,
                                                  size_t *cryptogram_sz);

bool
vs_converters_virgil_cryptogram_parse_mbedtls(const uint8_t *virgil_encrypted_data,
                                              size_t virgil_encrypted_data_sz,
                                              const uint8_t *recipient_id,
                                              size_t recipient_id_sz,
                                              uint8_t **iv,
                                              uint8_t **encrypted_key,
                                              size_t *encrypted_key_sz,
                                              uint8_t **encrypted_data,
                                              size_t *encrypted_data_sz);

bool
vs_converters_mbedtls_cryptogram_parse_low_level(const uint8_t *cryptogram,
                                                 size_t cryptogram_sz,
                                                 uint8_t **public_key,
                                                 uint8_t **iv,
                                                 uint8_t **hmac,
                                                 uint8_t **encrypted_data,
                                                 size_t *encrypted_data_sz);

#ifdef __cplusplus
}
#endif

#endif // VS_CRYPTO_CONVERTERS_H
