//
// Copyright (C) 2016 Virgil Security Inc.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//

/**
 * @file crypto_format_converters.h
 * @brief Cryptographic converters
 *
 * This file covers the following conversion cases :
 *
 * - Public key conversions :
 *  - #vs_converters_pubkey_to_raw() : from Virgil format to raw format
 *  - #vs_converters_pubkey_to_virgil() : from raw format to Virgil format
 * - Signatures :
 *  - #vs_converters_virgil_sign_to_raw() : from Virgil format to raw format
 *  - #vs_converters_raw_sign_to_virgil() : from raw format to Virgil format
 *  - #vs_converters_mbedtls_sign_to_raw() : from MbedTLS format to raw format
 *  - #vs_converters_raw_sign_to_mbedtls() : from raw format to MbedTLS format
 *
 *  Each function returns boolean value true if conversion has been successful and false in another case.
 */

#ifndef VS_CRYPTO_CONVERTERS_H
#define VS_CRYPTO_CONVERTERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <virgil/iot/secmodule/secmodule.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Convert public key from Virgil format to raw format
 *
 * \param[in] keypair_type Keypair type.
 * \param[in] public_key Source public key in Virgil format. Must not be NULL.
 * \param[in] public_key_sz Source public key size. Must not be zero.
 * \param[out] pubkey_raw Destination buffer for public key in raw format. Must not be NULL.
 * \param[in] buf_sz Output buffer size. Must not be zero.
 * \param[in] pubkey_raw_sz Pointer for saved public key size. Must not be NULL.
 *
 * \return true in case of success or false otherwise
 */
bool
vs_converters_pubkey_to_raw(vs_secmodule_keypair_type_e keypair_type,
                            const uint8_t *public_key,
                            uint16_t public_key_sz,
                            uint8_t *pubkey_raw,
                            uint16_t buf_sz,
                            uint16_t *pubkey_raw_sz);

/** Convert public key from raw format to Virgil format
 *
 * \param[in] keypair_type Keypair type.
 * \param[in] public_key_in Source public key in raw format. Must not be NULL.
 * \param[in] public_key_in_sz Source public key size. Must not be zero.
 * \param[out] public_key_out Destination buffer for public key in Virgil format. Must not be NULL.
 * \param[in] buf_sz Output buffer size. Must not be zero.
 * \param[in] public_key_out_sz Pointer for saved public key size. Must not be NULL.
 *
 * \return true in case of success or false otherwise
 */
bool
vs_converters_pubkey_to_virgil(vs_secmodule_keypair_type_e keypair_type,
                               const uint8_t *public_key_in,
                               uint16_t public_key_in_sz,
                               uint8_t *public_key_out,
                               uint16_t buf_sz,
                               uint16_t *public_key_out_sz);

/** Convert signature from Virgil format to raw format
 *
 * \param[in] keypair_type Keypair type.
 * \param[in] virgil_sign Source signature in Virgil format. Must not be NULL.
 * \param[in] virgil_sign_sz Source signature size. Must not be zero.
 * \param[out] sign Destination buffer for signature in raw format. Must not be NULL.
 * \param[in] buf_sz Output buffer size. Must not be zero.
 * \param[in] sign_sz Pointer to saved signature size. Must not be NULL.
 *
 * \return true in case of success and false otherwise
 */
bool
vs_converters_virgil_sign_to_raw(vs_secmodule_keypair_type_e keypair_type,
                                 const uint8_t *virgil_sign,
                                 uint16_t virgil_sign_sz,
                                 uint8_t *sign,
                                 uint16_t buf_sz,
                                 uint16_t *sign_sz);

/** Convert signature from raw format to Virgil format
 *
 * \param[in] keypair_type Keypair type.
 * \param[in] hash_type Hash type.
 * \param[in] raw_sign Source signature in raw format. Must not be NULL.
 * \param[in] raw_sign_sz Source signature size. Must not be zero.
 * \param[out] virgil_sign Destination buffer for signature in Virgil format. Must not be NULL.
 * \param[in] buf_sz Output buffer size. Must not be zero.
 * \param[in] virgil_sign_sz Pointer to saved signature size. Must not be NULL.
 *
 * \return true in case of success and false otherwise
 */
bool
vs_converters_raw_sign_to_virgil(vs_secmodule_keypair_type_e keypair_type,
                                 vs_secmodule_hash_type_e hash_type,
                                 const uint8_t *raw_sign,
                                 uint16_t raw_sign_sz,
                                 uint8_t *virgil_sign,
                                 uint16_t buf_sz,
                                 uint16_t *virgil_sign_sz);

/** Convert signature from MbedTLS format to raw format
 *
 * \param[in] keypair_type Keypair type.
 * \param[in] mbedtls_sign Source signature in MbedTLS format. Must not be NULL.
 * \param[in] mbedtls_sign_sz Source signature size. Must not be zero.
 * \param[out] raw_sign Destination buffer for signature in raw format. Must not be NULL.
 * \param[in] buf_sz Output buffer size. Must not be zero.
 * \param[in] raw_sz Pointer to saved signature size. Must not be NULL.
 *
 * \return true in case of success and false otherwise
 */
bool
vs_converters_mbedtls_sign_to_raw(vs_secmodule_keypair_type_e keypair_type,
                                  uint8_t *mbedtls_sign,
                                  uint16_t mbedtls_sign_sz,
                                  uint8_t *raw_sign,
                                  uint16_t buf_sz,
                                  uint16_t *raw_sz);

/** Convert signature from raw format to MbedTLS format
 *
 * \param[in] keypair_type Keypair type.
 * \param[in] raw Source signature in raw format. Must not be NULL.
 * \param[in] raw_sz Source signature size. Must not be zero.
 * \param[out] signature Destination buffer for signature in MbedTLS format. Must not be NULL.
 * \param[in] buf_sz Output buffer size. Must not be zero.
 * \param[in] signature_sz Pointer to saved signature size. Must not be NULL.
 *
 * \return true in case of success and false otherwise
 */
bool
vs_converters_raw_sign_to_mbedtls(vs_secmodule_keypair_type_e keypair_type,
                                  const unsigned char *raw,
                                  uint16_t raw_sz,
                                  unsigned char *signature,
                                  uint16_t buf_sz,
                                  uint16_t *signature_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_CRYPTO_CONVERTERS_H
