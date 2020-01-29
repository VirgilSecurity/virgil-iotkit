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
 * @file secmodule.h
 * @brief Security Module implementations signatures
 *
 * This header contains #vs_secmodule_impl_t structure that is used for crypto operations.
 *
 * \warning User needs to provide Security Module implementation. Library provides standard software implementation.
 * See \ref vs-secmodule-usage for example.
 *
 * \code

vs_secmodule_impl_t *secmodule_impl;                 // Security Module implementations
vs_storage_op_ctx_t slots_storage_impl;  // Slots storage implementation

// Virgil IoT KIT provides Software Security Module that can be used instead of Hardware one :
secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

// ... Library usage

vs_soft_secmodule_deinit();

 * \endcode
 *
 * Software Security Module needs to have Slots Storage Implementation initialized. See \ref storage_hal for details.
 */

#ifndef VS_SECMODULE_INTERFACE_API_H
#define VS_SECMODULE_INTERFACE_API_H

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/secmodule/devices/secmodule-soft.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Keypair types */
typedef enum {
    VS_KEYPAIR_INVALID = -1, /**< Invalid keypair */
    VS_KEYPAIR_EC_SECP_MIN = 1,
    VS_KEYPAIR_EC_SECP192R1 = VS_KEYPAIR_EC_SECP_MIN, /**< 192-bits NIST curve */
    VS_KEYPAIR_EC_SECP224R1,                          /**< 224-bits NIST curve */
    VS_KEYPAIR_EC_SECP256R1,                          /**< 256-bits NIST curve */
    VS_KEYPAIR_EC_SECP384R1,                          /**< 384-bits NIST curve */
    VS_KEYPAIR_EC_SECP521R1,                          /**< 521-bits NIST curve */
    VS_KEYPAIR_EC_SECP192K1,                          /**< 192-bits "Koblitz" curve */
    VS_KEYPAIR_EC_SECP224K1,                          /**< 224-bits "Koblitz" curve */
    VS_KEYPAIR_EC_SECP256K1,                          /**< 256-bits "Koblitz" curve */
    VS_KEYPAIR_EC_SECP_MAX = VS_KEYPAIR_EC_SECP256K1,
    VS_KEYPAIR_EC_CURVE25519, /**< Curve25519 */
    VS_KEYPAIR_EC_ED25519,    /**< Ed25519 */
    VS_KEYPAIR_MAX
} vs_secmodule_keypair_type_e;

/** Hash types */
typedef enum {
    VS_HASH_SHA_INVALID = -1, /**< Invalid hash type */
    VS_HASH_SHA_256 = 0,      /**< SHA-256 */
    VS_HASH_SHA_384,          /**< SHA-384*/
    VS_HASH_SHA_512,          /**< SHA-512*/
} vs_secmodule_hash_type_e;

/** KDF type */
typedef enum {
    VS_KDF_INVALID = -1,
    VS_KDF_2 = 0,
} vs_secmodule_kdf_type_e;

/** AES mode */
typedef enum {
    VS_AES_GCM, /**< AES-GCM */
    VS_AES_CBC  /**< AES-CBC */
} vs_iot_aes_type_e;

/** SHA-256 context */
typedef struct {
    uint32_t total[2];        /**< The number of bytes processed */
    uint32_t state[8];        /**< The intermediate digest state */
    unsigned char buffer[64]; /**< The data block being processed */
} vs_secmodule_sw_sha256_ctx;

/** Save information to the slot
 *
 * \param[in] slot Slot ID.
 * \param[in] data Data to be saved. Cannot be NULL.
 * \param[in] data_sz Data size. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_slot_save_t)(vs_iot_secmodule_slot_e slot, const uint8_t *data, uint16_t data_sz);

/** Load information to the slot
 *
 * \param[in] slot Slot ID.
 * \param[out] data Data buffer for loaded information. Cannot be NULL.
 * \param[in] buf_sz Buffer size. Cannot be zero.
 * \param[out] out_sz Loaded data size buffer. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_slot_load_t)(vs_iot_secmodule_slot_e slot,
                                                uint8_t *data,
                                                uint16_t buf_sz,
                                                uint16_t *out_sz);

/** Delete information from the slot
 *
 * \param[in] slot Slot ID.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_slot_delete_t)(vs_iot_secmodule_slot_e slot);

/** Hash generation
 *
 * \param[in] hash_type Hash type. Cannot by #VS_HASH_SHA_INVALID.
 * \param[in] data Data source for hash calculation. Cannot be NULL.
 * \param[in] data_sz Data size. Cannot be zero.
 * \param[out] hash Output buffer to store hash. Cannot be NULL.
 * \param[in] hash_buf_sz Output buffer size. Cannot be NULL.
 * \param[out] hash_sz Output buffer to store hash size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_hash_create_t)(vs_secmodule_hash_type_e hash_type,
                                                  const uint8_t *data,
                                                  uint16_t data_sz,
                                                  uint8_t *hash,
                                                  uint16_t hash_buf_sz,
                                                  uint16_t *hash_sz);

/** Key pair generate
 *
 * \param[in] slot Slot ID to save key pair.
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_keypair_create_t)(vs_iot_secmodule_slot_e slot,
                                                     vs_secmodule_keypair_type_e keypair_type);

/** Public key retrieval
 *
 * \note Before calling this function, you should call #vs_secmodule_keypair_create_t implementation first and store
 * public key in \a slot.
 *
 * \param[in] slot Slot number.
 * \param[out] buf Output buffer to store public key. Cannot be NULL.
 * \param[in] buf_sz Output buffer size. Cannot be NULL.
 * \param[out] key_sz Output buffer to store public key size. Cannot be NULL.
 * \param[out] keypair_type Output buffer to store key pair type. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_keypair_get_pubkey_t)(vs_iot_secmodule_slot_e slot,
                                                         uint8_t *buf,
                                                         uint16_t buf_sz,
                                                         uint16_t *key_sz,
                                                         vs_secmodule_keypair_type_e *keypair_type);

/** Signature calculation based on ECDSA
 *
 * \param[in] key_slot Slot number.
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 * \param[in] hash Hash source for signature calculation. Cannot be NULL.
 * \param[out] signature Output buffer to store signature. Cannot be NULL.
 * \param[in] signature_buf_sz Output buffer size. Cannot be NULL.
 * \param[out] signature_sz Output buffer to store signature size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_ecdsa_sign_t)(vs_iot_secmodule_slot_e key_slot,
                                                 vs_secmodule_hash_type_e hash_type,
                                                 const uint8_t *hash,
                                                 uint8_t *signature,
                                                 uint16_t signature_buf_sz,
                                                 uint16_t *signature_sz);

/** Signature verification based on ECDSA
 *
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 * \param[in] public_key Public key buffer. Cannot be NULL.
 * \param[in] public_key_sz Public key size. Cannot be zero.
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 * \param[in] hash Hash source for signature calculation. Cannot be NULL.
 * \param[in] signature Output buffer to store signature. Cannot be NULL.
 * \param[in] signature_sz Output buffer to store signature size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of successful verifying or error code.
 */
typedef vs_status_e (*vs_secmodule_ecdsa_verify_t)(vs_secmodule_keypair_type_e keypair_type,
                                                   const uint8_t *public_key,
                                                   uint16_t public_key_sz,
                                                   vs_secmodule_hash_type_e hash_type,
                                                   const uint8_t *hash,
                                                   const uint8_t *signature,
                                                   uint16_t signature_sz);

/** HMAC calculation
 *
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 * \param[in] key Key buffer. Cannot be NULL.
 * \param[in] key_sz Key size. Cannot be zero.
 * \param[in] input Input data. Cannot be NULL.
 * \param[in] input_sz Input data size. Cannot be zero.
 * \param[out] output Output buffer. Cannot be NULL.
 * \param[in] output_buf_sz Output buffer size. Cannot be NULL.
 * \param[out] output_sz Output buffer to store output data size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_hmac_t)(vs_secmodule_hash_type_e hash_type,
                                           const uint8_t *key,
                                           uint16_t key_sz,
                                           const uint8_t *input,
                                           uint16_t input_sz,
                                           uint8_t *output,
                                           uint16_t output_buf_sz,
                                           uint16_t *output_sz);

/** KDF calculation
 *
 * \param[in] kdf_type KDF algorithm. Cannot be #VS_KDF_INVALID.
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 * \param[in] input Input data. Cannot be NULL.
 * \param[in] input_sz Input data size. Cannot be zero.
 * \param[out] output Output key buffer. Cannot be NULL.
 * \param[in] output_sz Output key size. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_kdf_t)(vs_secmodule_kdf_type_e kdf_type,
                                          vs_secmodule_hash_type_e hash_type,
                                          const uint8_t *input,
                                          uint16_t input_sz,
                                          uint8_t *output,
                                          uint16_t output_sz);

/** HKDF calculation
 *
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 * \param[in] input Input data. Cannot be NULL.
 * \param[in] input_sz Input data size. Cannot be zero.
 * \param[in] salt Salt data. Cannot be NULL.
 * \param[in] salt_sz Salt data size. Cannot be zero.
 * \param[in] info Information data. Cannot be NULL.
 * \param[in] info_sz Information data size. Cannot be zero.
 * \param[out] output Output key buffer. Cannot be NULL.
 * \param[in] output_sz Output key size. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_hkdf_t)(vs_secmodule_hash_type_e hash_type,
                                           const uint8_t *input,
                                           uint16_t input_sz,
                                           const uint8_t *salt,
                                           uint16_t salt_sz,
                                           const uint8_t *info,
                                           uint16_t info_sz,
                                           uint8_t *output,
                                           uint16_t output_sz);

/** Random data generation
 *
 * \param[out] output Output buffer. Cannot be NULL.
 * \param[in] output_sz Output buffer size. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_random_t)(uint8_t *output, uint16_t output_sz);

/** Data encryption by AES algorithm
 *
 * \param[in] aes_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 * \param[in] key Key. Cannot be NULL.
 * \param[in] key_bitlen Key size in bits. Cannot be zero.
 * \param[in] iv IV. Cannot be NULL.
 * \param[in] iv_len IV size. Cannot be zero.
 * \param[in] add Additional data. Cannot be NULL.
 * \param[in] add_len Additional data size. Cannot be NULL.
 * \param[in] buf_len Buffer size. Cannot be zero.
 * \param[in] input Input buffer. Cannot be zero.
 * \param[out] output Output buffer. Cannot be NULL.
 * \param[out] tag Tag buffer. Cannot be NULL.
 * \param[in] tag_len Tag size. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_aes_encrypt_t)(vs_iot_aes_type_e aes_type,
                                                  const uint8_t *key,
                                                  uint16_t key_bitlen,
                                                  const uint8_t *iv,
                                                  uint16_t iv_len,
                                                  const uint8_t *add,
                                                  uint16_t add_len,
                                                  uint16_t buf_len,
                                                  const uint8_t *input,
                                                  uint8_t *output,
                                                  uint8_t *tag,
                                                  uint16_t tag_len);

/** Data decryption by AES algorithm
 *
 * \param[in] aes_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 * \param[in] key Key. Cannot be NULL.
 * \param[in] key_bitlen Key size in bits. Cannot be zero.
 * \param[in] iv IV. Cannot be NULL.
 * \param[in] iv_len IV size. Cannot be zero.
 * \param[in] add Additional data. Cannot be NULL.
 * \param[in] add_len Additional data size. Cannot be NULL.
 * \param[in] buf_len Buffer size. Cannot be zero.
 * \param[in] input Input buffer. Cannot be zero.
 * \param[out] output Output buffer. Cannot be NULL.
 * \param[out] tag Tag buffer. Cannot be NULL.
 * \param[in] tag_len Tag size. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_aes_decrypt_t)(vs_iot_aes_type_e aes_type,
                                                  const uint8_t *key,
                                                  uint16_t key_bitlen,
                                                  const uint8_t *iv,
                                                  uint16_t iv_len,
                                                  const uint8_t *add,
                                                  uint16_t add_len,
                                                  uint16_t buf_len,
                                                  const uint8_t *input,
                                                  uint8_t *output,
                                                  uint8_t *tag,
                                                  uint16_t tag_len);

/** Data decryption by AES algorithm with authentication check
 *
 * \param[in] aes_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 * \param[in] key Key. Cannot be NULL.
 * \param[in] key_bitlen Key size in bits. Cannot be zero.
 * \param[in] iv IV. Cannot be NULL.
 * \param[in] iv_len IV size. Cannot be zero.
 * \param[in] add Additional data. Cannot be NULL.
 * \param[in] add_len Additional data size. Cannot be NULL.
 * \param[in] buf_len Buffer size. Cannot be zero.
 * \param[in] input Input buffer. Cannot be zero.
 * \param[out] output Output buffer. Cannot be NULL.
 * \param[in] tag Tag buffer. Cannot be NULL.
 * \param[in] tag_len Tag size. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_aes_auth_decrypt_t)(vs_iot_aes_type_e aes_type,
                                                       const uint8_t *key,
                                                       uint16_t key_bitlen,
                                                       const uint8_t *iv,
                                                       uint16_t iv_len,
                                                       const uint8_t *add,
                                                       uint16_t add_len,
                                                       uint16_t buf_len,
                                                       const uint8_t *input,
                                                       uint8_t *output,
                                                       const uint8_t *tag,
                                                       uint16_t tag_len);

/** ECDH algorithm
 *
 * \param[in] key_slot Slot number.
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 * \param[in] public_key Public key buffer. Cannot be NULL.
 * \param[in] public_key_sz Public key size. Cannot be zero.
 * \param[in,out] shared_secret Shared secret buffer. Cannot be NULL.
 * \param[in] buf_sz Shared secret buffer size. Cannot be zero.
 * \param[out] shared_secret_sz Output buffer to store shared secret buffer size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_ecdh_t)(vs_iot_secmodule_slot_e slot,
                                           vs_secmodule_keypair_type_e keypair_type,
                                           const uint8_t *public_key,
                                           uint16_t public_key_sz,
                                           uint8_t *shared_secret,
                                           uint16_t buf_sz,
                                           uint16_t *shared_secret_sz);

/** SHA-256 context initialization
 *
 * \param[out] ctx Context. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef void (*vs_secmodule_sw_sha256_init_t)(vs_secmodule_sw_sha256_ctx *ctx);

/** SHA-256 context update
 *
 * \param[in,out] ctx Context.
 * \param[in] message Message update SHA-256 context. Cannot be NULL.
 * \param[in] len Message size. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_sw_sha256_update_t)(vs_secmodule_sw_sha256_ctx *ctx,
                                                       const uint8_t *message,
                                                       uint32_t len);

/** SHA-256 context finalization
 *
 * \param[in,out] ctx Context.
 * \param[out] digest Produced digest. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_secmodule_sw_sha256_final_t)(vs_secmodule_sw_sha256_ctx *ctx, uint8_t *digest);

/** Security Module destruction */
typedef void (*vs_secmodule_deinit_t)(void);

/** Security Module implementation
 *
 * This structure contains all implementations needed for cryptographic operations.
 * There are slot operations (load, save, clean) and cryptographic ones (RNG,  key pair, ECDSA, ECDH, AES, hash, HMAC,
 * HKDF, ECIES).
 */
typedef struct {

    vs_secmodule_deinit_t deinit; /**< Security module destruction */

    // Slot operations
    vs_secmodule_slot_save_t slot_save;    /**< Slot save information */
    vs_secmodule_slot_load_t slot_load;    /**< Slot load information */
    vs_secmodule_slot_delete_t slot_clean; /**< Slot delete */

    // RNG
    vs_secmodule_random_t random; /**< Get random data */

    // Key-pair in slot
    vs_secmodule_keypair_create_t create_keypair; /**< Key pair generation */
    vs_secmodule_keypair_get_pubkey_t get_pubkey; /**< Get public key */

    // ECDSA
    vs_secmodule_ecdsa_sign_t ecdsa_sign;     /**< ECDSA sign */
    vs_secmodule_ecdsa_verify_t ecdsa_verify; /**< ECDSA verify */

    // ECDH
    vs_secmodule_ecdh_t ecdh; /**< ECDH */

    // AES
    vs_secmodule_aes_encrypt_t aes_encrypt;           /**< AES encrypt */
    vs_secmodule_aes_decrypt_t aes_decrypt;           /**< AES decrypt */
    vs_secmodule_aes_auth_decrypt_t aes_auth_decrypt; /**< AES decrypt with authentication */

    // Hash
    vs_secmodule_sw_sha256_init_t hash_init;     /**< SHA-256 hash initialize */
    vs_secmodule_sw_sha256_update_t hash_update; /**< SHA-256 update */
    vs_secmodule_sw_sha256_final_t hash_finish;  /**< SHA-256 finalization */
    vs_secmodule_hash_create_t hash;             /**< Create hash */

    // HMAC
    vs_secmodule_hmac_t hmac; /**< HMAC calculate */

    // KDF
    vs_secmodule_kdf_t kdf; /**< KDF calculate */

    // HKDF
    vs_secmodule_hkdf_t hkdf; /**< HKDF calculate */

} vs_secmodule_impl_t;

/** ECIES decryption for AES-256 based on SHA-384
 *
 * \param[in] secmodule_impl Secmodule implementation. Cannot be NULL.
 * \param[in] recipient_id Recipient ID. Cannot be NULL.
 * \param[in] recipient_id_sz Recipient ID size. Cannot be NULL.
 * \param[in] cryptogram Cryptogram buffer. Cannot be NULL.
 * \param[in] cryptogram_sz Cryptogram buffer size. Cannot be NULL.
 * \param[out] decrypted_data Decrypted data output buffer. Cannot be NULL.
 * \param[in] buf_sz Decrypted data buffer size. Cannot be zero.
 * \param[out] decrypted_data_sz Decrypted data size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secmodule_ecies_decrypt(const vs_secmodule_impl_t *secmodule_impl,
                           const uint8_t *recipient_id,
                           size_t recipient_id_sz,
                           const uint8_t *cryptogram,
                           size_t cryptogram_sz,
                           uint8_t *decrypted_data,
                           size_t buf_sz,
                           size_t *decrypted_data_sz);

/** ECIES encryption for AES-256 based on SHA-384
 *
 * \param[in] secmodule_impl Secmodule implementation. Cannot be NULL.
 * \param[in] recipient_id Recipient ID. Cannot be NULL.
 * \param[in] recipient_id_sz Recipient ID size. Cannot be NULL.
 * \param[in] cryptogram Cryptogram buffer. Cannot be NULL.
 * \param[in] cryptogram_sz Cryptogram buffer size. Cannot be NULL.
 * \param[out] decrypted_data Decrypted data output buffer. Cannot be NULL.
 * \param[in] buf_sz Decrypted data buffer size. Cannot be zero.
 * \param[out] decrypted_data_sz Decrypted data size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secmodule_ecies_encrypt(const vs_secmodule_impl_t *secmodule_impl,
                           const uint8_t *recipient_id,
                           size_t recipient_id_sz,
                           const uint8_t *data,
                           size_t data_sz,
                           uint8_t *cryptogram,
                           size_t buf_sz,
                           size_t *cryptogram_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_SECMODULE_INTERFACE_API_H
