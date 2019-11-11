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

/**
 * @file hsm_helpers.h
 * @brief HSM helper functions
 */

#ifndef VS_HSM_HELPERS_H_
#define VS_HSM_HELPERS_H_

#include <virgil/iot/hsm/hsm.h>

#define VS_PUBKEY_SECP192_LEN (49)
#define VS_PUBKEY_SECP224_LEN (57)
#define VS_PUBKEY_SECP256_LEN (65)
#define VS_PUBKEY_SECP384_LEN (97)
#define VS_PUBKEY_SECP521_LEN (133)
#define VS_PUBKEY_25519_LEN (32)

#if USE_RSA
#define VS_PUBKEY_RSA2048_LEN (256)
#endif

#define VS_SIGNATURE_SECP192_LEN (48)
#define VS_SIGNATURE_SECP224_LEN (56)
#define VS_SIGNATURE_SECP256_LEN (64)
#define VS_SIGNATURE_SECP384_LEN (96)
#define VS_SIGNATURE_SECP521_LEN (132)
#define VS_SIGNATURE_25519_LEN (64)

#if USE_RSA
#define VS_SIGNATURE_RSA2048_LEN (256)
#endif

#define VS_HASH_SHA256_LEN (32)
#define VS_HASH_SHA384_LEN (48)
#define VS_HASH_SHA512_LEN (64)


/** Get public key length
 *
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Public key length
 */
int
vs_hsm_get_pubkey_len(vs_hsm_keypair_type_e keypair_type);

/** Get signature length
 *
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Signature length
 */
int
vs_hsm_get_signature_len(vs_hsm_keypair_type_e keypair_type);

/** Get hash length
 *
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 *
 * \return Hash length
 */
int
vs_hsm_get_hash_len(vs_hsm_hash_type_e hash_type);

/** Get key pair type description
 *
 * \param[in] type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Key pair description in static buffer
 */
const char *
vs_hsm_keypair_type_descr(vs_hsm_keypair_type_e type);

/** Get hash type description
 *
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 *
 * \return Hash type description in static buffer
 */
const char *
vs_hsm_hash_type_descr(vs_hsm_hash_type_e type);


/** Parse asn1 cryptogram in virgil format with sha384 hmac and encrypted data by AES256 GCM
 *
 * \param[in] cryptogram Pointer to cryptogram array for parsing. Cannot be NULL.
 * \param[in] cryptogram_sz Size of cryptogram array.
 * \param[in] recipient_id Pointer to recipient_id array. If NULL, it won't be used.
 * \param[in] recipient_id_sz  Size of recipient_id array.
 * \param[out] public_key Pointer to the recipient public key. Cannot be NULL.
 * \param[out] iv_key Pointer to the iv vector of encrypted symmetric AES GCM key. Cannot be NULL.
 * \param[out] encrypted_key Pointer to the encrypted symmetric AES GCM key. Cannot be NULL.
 * \param[out] mac_data Pointer to the authentication data. Cannot be NULL.
 * \param[out] iv_data Pointer to the iv vector of encrypted data. Cannot be NULL.
 * \param[out] encrypted_data Pointer to the encrypted data. Cannot be NULL.
 * \param[out] encrypted_data_sz Pointer to encrypted data size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_hsm_virgil_cryptogram_parse_sha384_aes256(const uint8_t *cryptogram,
                                             size_t cryptogram_sz,
                                             const uint8_t *recipient_id,
                                             size_t recipient_id_sz,
                                             uint8_t **public_key,
                                             uint8_t **iv_key,
                                             uint8_t **encrypted_key,
                                             uint8_t **mac_data,
                                             uint8_t **iv_data,
                                             uint8_t **encrypted_data,
                                             size_t *encrypted_data_sz);

/** Create asn1 cryptogram in virgil format with sha384 hmac and encrypted data by AES256 GCM
 *
 * \param[in] recipient_id Pointer to recipient_id array. Cannot be NULL.
 * \param[in] recipient_id_sz  Size of recipient_id array.
 * \param[in] encrypted_data_sz Size of encrypted data.
 * \param[in] encrypted_data Pointer to the encrypted data. Cannot be NULL.
 * \param[in] iv_data Pointer to the iv vector of encrypted data. Cannot be NULL.
 * \param[in] encrypted_key Pointer to the encrypted symmetric AES GCM key. Cannot be NULL.
 * \param[in] iv_key Pointer to the iv vector of encrypted symmetric AES GCM key. Cannot be NULL.
 * \param[in] hmac Pointer to the authentication data. Cannot be NULL.
 * \param[in] public_key Pointer to the recipient public key. Cannot be NULL.
 * \param[in] public_key_sz Recipient public key size.
 * \param[out] cryptogram Pointer to the buffer for created cryptogram. Cannot be NULL.
 * \param[in] cryptogram_buf_sz Size of buffer for created cryptogram. Cannot be 0.
 * \param[out] cryptogram_sz Pointer to size of created cryptogram. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_hsm_virgil_cryptogram_create_sha384_aes256(const uint8_t *recipient_id,
                                              size_t recipient_id_sz,
                                              size_t encrypted_data_sz,
                                              const uint8_t *encrypted_data,
                                              const uint8_t *iv_data,
                                              const uint8_t *encrypted_key,
                                              const uint8_t *iv_key,
                                              const uint8_t *hmac,
                                              const uint8_t *public_key,
                                              size_t public_key_sz,
                                              uint8_t *cryptogram,
                                              size_t cryptogram_buf_sz,
                                              size_t *cryptogram_sz);

/** Convert a nist256 signature from a virgil format to raw
 *
 * \param[in] virgil_sign Pointer to the signature in virgil format. Cannot be NULL.
 * \param[in] virgil_sign_sz Size of the signature in virgil format.
 * \param[out] raw_signature Pointer to the signature in raw format. Cannot be NULL.
 * \param[in] buf_sz Size of buffer for raw signature
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_hsm_virgil_secp256_signature_to_tiny(const uint8_t *virgil_sign,
                                        uint16_t virgil_sign_sz,
                                        uint8_t *raw_signature,
                                        uint16_t buf_sz);

#endif // VS_HSM_HELPERS_H_
