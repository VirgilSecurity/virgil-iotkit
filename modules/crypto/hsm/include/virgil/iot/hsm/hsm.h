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

#ifndef VS_HSM_INTERFACE_API_H
#define VS_HSM_INTERFACE_API_H

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/status_code/status_code.h>

#include <virgil/iot/hsm/devices/hsm_none.h>
#include <virgil/iot/hsm/devices/hsm_custom.h>
#include <virgil/iot/hsm/devices/hsm_atecc_508a.h>
#include <virgil/iot/hsm/devices/hsm_atecc_608a.h>
#include <virgil/iot/hsm/devices/hsm_iotelic.h>

typedef enum {
    VS_KEYPAIR_INVALID = -1,
    VS_KEYPAIR_EC_SECP_MIN = 1,
    VS_KEYPAIR_EC_SECP192R1 = VS_KEYPAIR_EC_SECP_MIN, ///< 192-bits NIST curve
    VS_KEYPAIR_EC_SECP224R1,                          ///< 224-bits NIST curve
    VS_KEYPAIR_EC_SECP256R1,                          ///< 256-bits NIST curve
    VS_KEYPAIR_EC_SECP384R1,                          ///< 384-bits NIST curve
    VS_KEYPAIR_EC_SECP521R1,                          ///< 521-bits NIST curve
    VS_KEYPAIR_EC_SECP192K1,                          ///< 192-bits "Koblitz" curve
    VS_KEYPAIR_EC_SECP224K1,                          ///< 224-bits "Koblitz" curve
    VS_KEYPAIR_EC_SECP256K1,                          ///< 256-bits "Koblitz" curve
    VS_KEYPAIR_EC_SECP_MAX = VS_KEYPAIR_EC_SECP256K1,
    VS_KEYPAIR_EC_CURVE25519, ///< Curve25519
    VS_KEYPAIR_EC_ED25519,    ///< Ed25519
    VS_KEYPAIR_RSA_2048,      ///< RSA 2048 bit (not recommended)
    VS_KEYPAIR_MAX
} vs_hsm_keypair_type_e;

typedef enum {
    VS_HASH_SHA_INVALID = -1,
    VS_HASH_SHA_256 = 0,
    VS_HASH_SHA_384,
    VS_HASH_SHA_512,
} vs_hsm_hash_type_e;

typedef enum {
    VS_KDF_INVALID = -1,
    VS_KDF_2 = 0,
} vs_hsm_kdf_type_e;

typedef enum { VS_AES_GCM, VS_AES_CBC } vs_iot_aes_type_e;

typedef struct {
    uint32_t total[2];        /*!< The number of Bytes processed.  */
    uint32_t state[8];        /*!< The intermediate digest state.  */
    unsigned char buffer[64]; /*!< The data block being processed. */
} vs_hsm_sw_sha256_ctx;

typedef vs_status_e (*vs_hsm_slot_save_t)(vs_iot_hsm_slot_e slot, const uint8_t *data, uint16_t data_sz);

typedef vs_status_e (*vs_hsm_slot_load_t)(vs_iot_hsm_slot_e slot, uint8_t *data, uint16_t buf_sz, uint16_t *out_sz);

typedef vs_status_e (*vs_hsm_slot_delete_t)(vs_iot_hsm_slot_e slot);

typedef vs_status_e (*vs_hsm_hash_create_t)(vs_hsm_hash_type_e hash_type,
                                            const uint8_t *data,
                                            uint16_t data_sz,
                                            uint8_t *hash,
                                            uint16_t hash_buf_sz,
                                            uint16_t *hash_sz);

typedef vs_status_e (*vs_hsm_keypair_create_t)(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type);

typedef vs_status_e (*vs_hsm_keypair_get_pubkey_t)(vs_iot_hsm_slot_e slot,
                                                   uint8_t *buf,
                                                   uint16_t buf_sz,
                                                   uint16_t *key_sz,
                                                   vs_hsm_keypair_type_e *keypair_type);

typedef vs_status_e (*vs_hsm_ecdsa_sign_t)(vs_iot_hsm_slot_e key_slot,
                                           vs_hsm_hash_type_e hash_type,
                                           const uint8_t *hash,
                                           uint8_t *signature,
                                           uint16_t signature_buf_sz,
                                           uint16_t *signature_sz);

typedef vs_status_e (*vs_hsm_ecdsa_verify_t)(vs_hsm_keypair_type_e keypair_type,
                                             const uint8_t *public_key,
                                             uint16_t public_key_sz,
                                             vs_hsm_hash_type_e hash_type,
                                             const uint8_t *hash,
                                             const uint8_t *signature,
                                             uint16_t signature_sz);

typedef vs_status_e (*vs_hsm_hmac_t)(vs_hsm_hash_type_e hash_type,
                                     const uint8_t *key,
                                     uint16_t key_sz,
                                     const uint8_t *input,
                                     uint16_t input_sz,
                                     uint8_t *output,
                                     uint16_t output_buf_sz,
                                     uint16_t *output_sz);

typedef vs_status_e (*vs_hsm_kdf_t)(vs_hsm_kdf_type_e kdf_type,
                                    vs_hsm_hash_type_e hash_type,
                                    const uint8_t *input,
                                    uint16_t input_sz,
                                    uint8_t *output,
                                    uint16_t output_sz);

typedef vs_status_e (*vs_hsm_hkdf_t)(vs_hsm_hash_type_e hash_type,
                                     const uint8_t *input,
                                     uint16_t input_sz,
                                     const uint8_t *salt,
                                     uint16_t salt_sz,
                                     const uint8_t *info,
                                     uint16_t info_sz,
                                     uint8_t *output,
                                     uint16_t output_sz);

typedef vs_status_e (*vs_hsm_random_t)(uint8_t *output, uint16_t output_sz);

typedef vs_status_e (*vs_hsm_aes_encrypt_t)(vs_iot_aes_type_e aes_type,
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

typedef vs_status_e (*vs_hsm_aes_decrypt_t)(vs_iot_aes_type_e aes_type,
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

typedef vs_status_e (*vs_hsm_aes_auth_decrypt_t)(vs_iot_aes_type_e aes_type,
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

typedef vs_status_e (*vs_hsm_ecdh_t)(vs_iot_hsm_slot_e slot,
                                     vs_hsm_keypair_type_e keypair_type,
                                     const uint8_t *public_key,
                                     uint16_t public_key_sz,
                                     uint8_t *shared_secret,
                                     uint16_t buf_sz,
                                     uint16_t *shared_secret_sz);

typedef void (*vs_hsm_sw_sha256_init_t)(vs_hsm_sw_sha256_ctx *ctx);

typedef vs_status_e (*vs_hsm_sw_sha256_update_t)(vs_hsm_sw_sha256_ctx *ctx, const uint8_t *message, uint32_t len);

typedef vs_status_e (*vs_hsm_sw_sha256_final_t)(vs_hsm_sw_sha256_ctx *ctx, uint8_t *digest);

typedef vs_status_e (*vs_hsm_virgil_decrypt_sha384_aes256_t)(const uint8_t *recipient_id,
                                                             size_t recipient_id_sz,
                                                             uint8_t *cryptogram,
                                                             size_t cryptogram_sz,
                                                             uint8_t *decrypted_data,
                                                             size_t buf_sz,
                                                             size_t *decrypted_data_sz);

typedef vs_status_e (*vs_hsm_virgil_encrypt_sha384_aes256_t)(const uint8_t *recipient_id,
                                                             size_t recipient_id_sz,
                                                             uint8_t *data,
                                                             size_t data_sz,
                                                             uint8_t *cryptogram,
                                                             size_t buf_sz,
                                                             size_t *cryptogram_sz);

typedef void (*vs_hsm_deinit_t)(void);

typedef struct {

    vs_hsm_deinit_t deinit;

    // Slot operations
    vs_hsm_slot_save_t slot_save;
    vs_hsm_slot_load_t slot_load;
    vs_hsm_slot_delete_t slot_clean;

    // RNG
    vs_hsm_random_t random;

    // Key-pair in slot
    vs_hsm_keypair_create_t create_keypair;
    vs_hsm_keypair_get_pubkey_t get_pubkey;

    // ECDSA
    vs_hsm_ecdsa_sign_t ecdsa_sign;
    vs_hsm_ecdsa_verify_t ecdsa_verify;

    // ECDH
    vs_hsm_ecdh_t ecdh;

    // AES
    vs_hsm_aes_encrypt_t aes_encrypt;
    vs_hsm_aes_decrypt_t aes_decrypt;
    // TODO: Remove it
    vs_hsm_aes_auth_decrypt_t aes_auth_decrypt;

    // Hash
    vs_hsm_sw_sha256_init_t hash_init;
    vs_hsm_sw_sha256_update_t hash_update;
    vs_hsm_sw_sha256_final_t hash_finish;
    vs_hsm_hash_create_t hash;

    // HMAC
    vs_hsm_hmac_t hmac;

    // KDF
    vs_hsm_kdf_t kdf;

    // HKDF
    vs_hsm_hkdf_t hkdf;

    // ECIES
    vs_hsm_virgil_encrypt_sha384_aes256_t ecies_encrypt;
    vs_hsm_virgil_decrypt_sha384_aes256_t ecies_decrypt;
} vs_hsm_impl_t;

#endif // VS_HSM_INTERFACE_API_H
