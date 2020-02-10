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

/**
 * @file secmodule-helpers.h
 * @brief Security module helper functions
 *
 * This header contains different helper functions for performing cryptographic operations
 */

#ifndef VS_SECMODULE_HELPERS_H_
#define VS_SECMODULE_HELPERS_H_

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#include <virgil/iot/secmodule/secmodule.h>

#define VS_PUBKEY_SECP192_LEN (49)
#define VS_PUBKEY_SECP224_LEN (57)
#define VS_PUBKEY_SECP256_LEN (65)
#define VS_PUBKEY_SECP384_LEN (97)
#define VS_PUBKEY_SECP521_LEN (133)
#define VS_PUBKEY_25519_LEN (32)

#define VS_SIGNATURE_SECP192_LEN (48)
#define VS_SIGNATURE_SECP224_LEN (56)
#define VS_SIGNATURE_SECP256_LEN (64)
#define VS_SIGNATURE_SECP384_LEN (96)
#define VS_SIGNATURE_SECP521_LEN (132)
#define VS_SIGNATURE_25519_LEN (64)

#define VS_HASH_SHA256_LEN (32)
#define VS_HASH_SHA384_LEN (48)
#define VS_HASH_SHA512_LEN (64)

#define VS_AES_256_KEY_SIZE (32)
#define VS_AES_256_KEY_BITLEN (VS_AES_256_KEY_SIZE * 8)
#define VS_AES_256_BLOCK_SIZE (16)

#define VS_AES_256_GCM_IV_SIZE (12)
#define VS_AES_256_GCM_AUTH_TAG_SIZE (16)

#define VS_AES_256_CBC_IV_SIZE (16)

/** Get public key length
 *
 * This function returns public key length for supported and enabled key pair types.
 *
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Public key length
 */
int
vs_secmodule_get_pubkey_len(vs_secmodule_keypair_type_e keypair_type);

/** Get signature length
 *
 * This function returns signature length for supported and enabled signature types.
 *
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Signature length
 */
int
vs_secmodule_get_signature_len(vs_secmodule_keypair_type_e keypair_type);

/** Get hash length
 *
 * This function returns hash length for supported and enabled hash types.
 *
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 *
 * \return Hash length
 */
int
vs_secmodule_get_hash_len(vs_secmodule_hash_type_e hash_type);

/** Get key pair type description
 *
 * This function returns key pair ASCIIZ description for supported and enable key pair types
 *
 * \param[in] type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Key pair description in static buffer
 */
const char *
vs_secmodule_keypair_type_descr(vs_secmodule_keypair_type_e type);

/** Get hash type description
 *
 * This function returns hash ASCIIZ description for supported and enable hash types
 *
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 *
 * \return Hash type description in static buffer
 */
const char *
vs_secmodule_hash_type_descr(vs_secmodule_hash_type_e type);

/** Convert a NIST256 signature from a Virgil format to raw
 *
 * \param[in] virgil_sign Pointer to the signature in Virgil format. Cannot be NULL.
 * \param[in] virgil_sign_sz Size of the signature in Virgil format.
 * \param[out] raw_signature Pointer to the signature in raw format. Cannot be NULL.
 * \param[in] buf_sz Size of buffer for raw signature
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secmodule_virgil_secp256_signature_to_tiny(const uint8_t *virgil_sign,
                                              uint16_t virgil_sign_sz,
                                              uint8_t *raw_signature,
                                              uint16_t buf_sz);

/** Convert a NIST-256 signature from raw format to Virgil format
 *
 * \param[in] raw_signature Pointer to the signature in raw format. Cannot be NULL.
 * \param[in] virgil_sign Pointer to the signature in Virgil format. Cannot be NULL.
 * \param[in] buf_sz Size of buffer for raw signature
 * \param[out] virgil_sign_sz Pointer to size of the signature in Virgil format. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secmodule_tiny_secp256_signature_to_virgil(const uint8_t raw_signature[VS_SIGNATURE_SECP256_LEN],
                                              uint8_t *virgil_sign,
                                              uint16_t buf_sz,
                                              uint16_t *virgil_sign_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_SECMODULE_HELPERS_H_
