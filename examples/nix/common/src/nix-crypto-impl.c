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

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/converters/crypto_format_converters.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/status_code/status_code.h>

#include <virgil/crypto/foundation/vscf_secp256r1_private_key.h>
#include <virgil/crypto/foundation/vscf_secp256r1_public_key.h>
#include <virgil/crypto/foundation/vscf_curve25519_private_key.h>
#include <virgil/crypto/foundation/vscf_curve25519_public_key.h>
#include <virgil/crypto/foundation/vscf_ed25519_private_key.h>
#include <virgil/crypto/foundation/vscf_ed25519_public_key.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_rsa_private_key.h>
#include <virgil/crypto/foundation/vscf_rsa_public_key.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_sha384.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_sign_hash.h>
#include <virgil/crypto/foundation/vscf_verify_hash.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_compute_shared_key.h>
#include <virgil/crypto/foundation/vscf_aes256_gcm.h>
#include <virgil/crypto/foundation/vscf_aes256_cbc.h>
#include <virgil/crypto/foundation/vscf_kdf2.h>
#include <virgil/crypto/foundation/vscf_hmac.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/vsc_data.h>
#include <nix-file-io.h>
#include <nix-crypto-impl.h>

#define RNG_MAX_REQUEST (256)

#define CHECK_VSCF(OPERATION, DESCRIPTION, ...)                                                                        \
    BOOL_CHECK((vscf_status_SUCCESS == (OPERATION)), DESCRIPTION, ##__VA_ARGS__)

// memory layout for keypair save/load buffer:
// . uint8_t key_type
// . uint8_t prvkey_sz
// . uint8_t prvkey[]
// . uint8_t pubkey_sz
// . uint8_t pubkey[]

#define KEYPAIR_BUF_KEYSZ_SIZEOF 1

#define KEYPAIR_BUF_KEYTYPE_OFF 0
#define KEYPAIR_BUF_KEYTYPE_SIZEOF 1

#define KEYPAIR_BUF_PRVKEYSZ_OFF (KEYPAIR_BUF_KEYTYPE_OFF + KEYPAIR_BUF_KEYTYPE_SIZEOF)
#define KEYPAIR_BUF_PRVKEYSZ_SIZEOF KEYPAIR_BUF_KEYSZ_SIZEOF

#define KEYPAIR_BUF_PRVKEY_OFF (KEYPAIR_BUF_PRVKEYSZ_OFF + KEYPAIR_BUF_PRVKEYSZ_SIZEOF)
#define KEYPAIR_BUF_PRVKEY_SIZEOF(BUF) ((BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF])

#define KEYPAIR_BUF_PUBKEYSZ_OFF(BUF) (KEYPAIR_BUF_PRVKEY_OFF + KEYPAIR_BUF_PRVKEY_SIZEOF(BUF))
#define KEYPAIR_BUF_PUBKEYSZ_SIZEOF KEYPAIR_BUF_KEYSZ_SIZEOF

#define KEYPAIR_BUF_PUBKEY_OFF(BUF) (KEYPAIR_BUF_PUBKEYSZ_OFF(BUF) + KEYPAIR_BUF_PUBKEYSZ_SIZEOF)
#define KEYPAIR_BUF_PUBKEY_SIZEOF(BUF) ((BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)])

#define KEYPAIR_BUF_SZ ((KEYPAIR_BUF_KEYTYPE_SIZEOF) + ((MAX_KEY_SZ + KEYPAIR_BUF_KEYSZ_SIZEOF) * 2))

#define ADD_KEYTYPE(BUF, KEYRPAIR_BUF, KEYPAIR_TYPE)                                                                   \
    do {                                                                                                               \
        (BUF)[KEYPAIR_BUF_KEYTYPE_OFF] = (KEYPAIR_TYPE);                                                               \
        vsc_buffer_inc_used(&(KEYRPAIR_BUF), KEYPAIR_BUF_KEYTYPE_SIZEOF);                                              \
    } while (0)

#define ADD_PRVKEYSZ(BUF, KEYPAIR_BUF, KEYSZ)                                                                          \
    do {                                                                                                               \
        if ((KEYSZ) > MAX_KEY_SZ) {                                                                                    \
            VS_LOG_ERROR("Too big private key : %d bytes. Maximum allowed size : %d", (KEYSZ), MAX_KEY_SZ);            \
            goto terminate;                                                                                            \
        }                                                                                                              \
        (BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF] = (KEYSZ);                                                                     \
        vsc_buffer_inc_used(&(KEYPAIR_BUF), KEYPAIR_BUF_PRVKEYSZ_SIZEOF);                                              \
    } while (0)

#define LOG_PRVKEY(BUF)                                                                                                \
    do {                                                                                                               \
        VS_LOG_DEBUG("Private key size : %d", (BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF]);                                        \
        VS_LOG_HEX(                                                                                                    \
                VS_LOGLEV_DEBUG, "Private key : ", (BUF) + KEYPAIR_BUF_PRVKEY_OFF, (BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF]);   \
    } while (0)

#define ADD_PUBKEYSZ(BUF, KEYPAIR_BUF, KEYSZ)                                                                          \
    do {                                                                                                               \
        if ((KEYSZ) > MAX_KEY_SZ) {                                                                                    \
            VS_LOG_ERROR("Too big public key : %d bytes. Maximum allowed size : %d", (KEYSZ), MAX_KEY_SZ);             \
            goto terminate;                                                                                            \
        }                                                                                                              \
        (BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)] = (KEYSZ);                                                                \
        vsc_buffer_inc_used(&(KEYPAIR_BUF), KEYPAIR_BUF_PUBKEYSZ_SIZEOF);                                              \
    } while (0)

#define LOG_PUBKEY(BUF)                                                                                                \
    do {                                                                                                               \
        VS_LOG_DEBUG("Public key size : %d", (BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)]);                                    \
        VS_LOG_HEX(VS_LOGLEV_DEBUG,                                                                                    \
                   "Public key : ",                                                                                    \
                   (BUF) + KEYPAIR_BUF_PUBKEY_OFF(BUF),                                                                \
                   (BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)]);                                                              \
    } while (0)

static const char *slots_dir = "slots";

/********************************************************************************/
vs_status_e
vs_hsm_hash_create(vs_hsm_hash_type_e hash_type,
                   const uint8_t *data,
                   uint16_t data_sz,
                   uint8_t *hash,
                   uint16_t hash_buf_sz,
                   uint16_t *hash_sz) {
    vsc_data_t in_data;
    vsc_buffer_t out_data;
    vs_status_e res = VS_CODE_ERR_CRYPTO;

    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_LOG_DEBUG("Generate hash %s for data size %d", vs_hsm_hash_type_descr(hash_type), data_sz);

    in_data = vsc_data(data, data_sz);

    vsc_buffer_init(&out_data);
    vsc_buffer_use(&out_data, hash, hash_buf_sz);

    switch (hash_type) {
        case VS_HASH_SHA_256:
            vscf_sha256_hash(in_data, &out_data);
            break;

        case VS_HASH_SHA_384:
            vscf_sha384_hash(in_data, &out_data);
            break;

        case VS_HASH_SHA_512:
            vscf_sha512_hash(in_data, &out_data);
            break;

        default:
            assert(false && "Unsupported hash type");
            VS_LOG_ERROR("Unsupported hash type");
            goto terminate;
    }

    *hash_sz = vsc_buffer_len(&out_data);

    VS_LOG_DEBUG("Hash size %d, type %s", *hash_sz, vs_hsm_hash_type_descr(hash_type));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Hash : ", hash, *hash_sz);

    res = VS_CODE_OK;

    terminate:

    if (VS_CODE_OK != res) {
        vsc_buffer_cleanup(&out_data);
    }

    return res;
}

/********************************************************************************/
static vs_status_e
_load_prvkey(vs_iot_hsm_slot_e key_slot, vscf_impl_t **prvkey, vs_hsm_keypair_type_e *keypair_type) {
    uint8_t prvkey_buf[MAX_KEY_SZ];
    uint16_t prvkey_buf_sz = sizeof(prvkey_buf);
    vsc_data_t prvkey_data;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    CHECK_NOT_ZERO_RET(prvkey, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(keypair_type, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(vs_hsm_keypair_get_prvkey(key_slot, prvkey_buf, prvkey_buf_sz, &prvkey_buf_sz, keypair_type),
                     "Unable to load private key data from slot %s",
                     get_slot_name(key_slot));

    prvkey_data = vsc_data(prvkey_buf, prvkey_buf_sz);

    switch (*keypair_type) {
        case VS_KEYPAIR_EC_SECP256R1:
            *prvkey = vscf_secp256r1_private_key_impl(vscf_secp256r1_private_key_new());
            CHECK_VSCF(vscf_secp256r1_private_key_import_private_key((vscf_secp256r1_private_key_t *)*prvkey, prvkey_data),
                       "Unable to import private key");
            break;

        case VS_KEYPAIR_EC_CURVE25519:
            *prvkey = vscf_curve25519_private_key_impl(vscf_curve25519_private_key_new());
            CHECK_VSCF(
                    vscf_curve25519_private_key_import_private_key((vscf_curve25519_private_key_t *)*prvkey, prvkey_data),
                    "Unable to import private key");
            break;

        case VS_KEYPAIR_EC_ED25519:
            *prvkey = vscf_ed25519_private_key_impl(vscf_ed25519_private_key_new());
            CHECK_VSCF(vscf_ed25519_private_key_import_private_key((vscf_ed25519_private_key_t *)*prvkey, prvkey_data),
                       "Unable to import private key");
            break;

        case VS_KEYPAIR_RSA_2048:
            *prvkey = vscf_rsa_private_key_impl(vscf_rsa_private_key_new());
            CHECK_VSCF(vscf_rsa_private_key_import_private_key((vscf_rsa_private_key_t *)*prvkey, prvkey_data),
                       "Unable to import private key");
            break;


        default:
            assert(false && "Unsupported keypair type");
            VS_LOG_ERROR("Unsupported keypair type %d (%s)", keypair_type, vs_hsm_keypair_type_descr(*keypair_type));
            ret_code = VS_CODE_ERR_NOT_IMPLEMENTED;
            goto terminate;
    }

    ret_code = VS_CODE_OK;

    terminate:

    return ret_code;
}

/********************************************************************************/
static vs_status_e
_create_pubkey_ctx(vs_hsm_keypair_type_e keypair_type,
                   const uint8_t *public_key,
                   uint16_t public_key_sz,
                   vscf_impl_t **pubkey) {
    vs_status_e res = VS_CODE_OK;

    *pubkey = NULL;

    switch (keypair_type) {
        case VS_KEYPAIR_EC_SECP256R1:
            *pubkey = vscf_secp256r1_public_key_impl(vscf_secp256r1_public_key_new());
            CHECK_RET(vscf_status_SUCCESS ==
                      vscf_secp256r1_public_key_import_public_key((vscf_secp256r1_public_key_t *)*pubkey,
                                                                  vsc_data(public_key, public_key_sz)),
                      VS_CODE_ERR_CRYPTO,
                      "Unable to import public key");
            break;

        case VS_KEYPAIR_EC_CURVE25519:
            *pubkey = vscf_curve25519_public_key_impl(vscf_curve25519_public_key_new());
            CHECK_RET(vscf_status_SUCCESS ==
                      vscf_curve25519_public_key_import_public_key((vscf_curve25519_public_key_t *)*pubkey,
                                                                   vsc_data(public_key, public_key_sz)),
                      VS_CODE_ERR_CRYPTO,
                      "Unable to import public key");
            break;

        case VS_KEYPAIR_EC_ED25519:
            *pubkey = vscf_ed25519_public_key_impl(vscf_ed25519_public_key_new());
            CHECK_RET(vscf_status_SUCCESS == vscf_ed25519_public_key_import_public_key((vscf_ed25519_public_key_t *)*pubkey,
                                                                                       vsc_data(public_key, public_key_sz)),
                      VS_CODE_ERR_CRYPTO,
                      "Unable to import public key");
            break;

        case VS_KEYPAIR_RSA_2048:
            *pubkey = vscf_rsa_public_key_impl(vscf_rsa_public_key_new());
            CHECK_RET(vscf_status_SUCCESS == vscf_rsa_public_key_import_public_key((vscf_rsa_public_key_t *)*pubkey,
                                                                                   vsc_data(public_key, public_key_sz)),
                      VS_CODE_ERR_CRYPTO,
                      "Unable to import public key");
            break;

        default:
            VS_LOG_ERROR("Unsupported keypair type %d (%s)", keypair_type, vs_hsm_keypair_type_descr(keypair_type));
            res = VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    return res;
}

/********************************************************************************/
static bool
_set_hash_info(vs_hsm_hash_type_e hash_type, vscf_alg_id_t *hash_id, uint16_t *hash_sz) {

    *hash_sz = (uint16_t)vs_hsm_get_hash_len(hash_type);

    switch (hash_type) {
        case VS_HASH_SHA_256:
            *hash_id = vscf_alg_id_SHA256;
            return true;

        case VS_HASH_SHA_384:
            *hash_id = vscf_alg_id_SHA384;
            return true;

        case VS_HASH_SHA_512:
            *hash_id = vscf_alg_id_SHA512;
            return true;

        default:
            VS_LOG_ERROR("Unsupported hash type %d", hash_type);
            return false;
    }
}

/********************************************************************************/
vs_status_e
vs_hsm_ecdsa_sign(vs_iot_hsm_slot_e key_slot,
                  vs_hsm_hash_type_e hash_type,
                  const uint8_t *hash,
                  uint8_t *signature,
                  uint16_t signature_buf_sz,
                  uint16_t *signature_sz) {
    vscf_impl_t *prvkey = NULL;
    vscf_alg_id_t hash_id = vscf_alg_id_NONE;
    uint16_t hash_sz = 0;
    vsc_buffer_t sign_data;
    vs_hsm_keypair_type_e keypair_type = VS_KEYPAIR_INVALID;
    uint16_t required_sign_sz = 0;
    vs_status_e res = VS_CODE_ERR_CRYPTO;

    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    vsc_buffer_init(&sign_data);

    BOOL_CHECK(_set_hash_info(hash_type, &hash_id, &hash_sz), "Unable to set hash info");

    BOOL_CHECK(VS_CODE_OK == _load_prvkey(key_slot, &prvkey, &keypair_type),
               "Unable to load private key from slot %d (%s)",
               key_slot,
               get_slot_name((key_slot)));

    required_sign_sz = vscf_sign_hash_signature_len(prvkey);

    vsc_buffer_alloc(&sign_data, required_sign_sz);

    CHECK_VSCF(vscf_sign_hash(prvkey, vsc_data(hash, hash_sz), hash_id, &sign_data), "Unable to sign data");

    *signature_sz = vsc_buffer_len(&sign_data);

    VS_LOG_DEBUG("Internal signature size : %d bytes", *signature_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Internal signature : ", vsc_buffer_begin(&sign_data), *signature_sz);

    BOOL_CHECK(vs_converters_mbedtls_sign_to_raw(keypair_type,
                                                 vsc_buffer_begin(&sign_data),
                                                 *signature_sz,
                                                 signature,
                                                 signature_buf_sz,
                                                 signature_sz),
               "Unable to convert Virgil signature format to the raw one");

    VS_LOG_DEBUG("Output signature size : %d bytes", *signature_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Output signature : ", signature, *signature_sz);

    res = VS_CODE_OK;

    terminate:
    vsc_buffer_release(&sign_data);

    if (prvkey) {
        vscf_impl_destroy(&prvkey);
    }

    return res;
}

/********************************************************************************/
vs_status_e
vs_hsm_ecdsa_verify(vs_hsm_keypair_type_e keypair_type,
                    const uint8_t *public_key,
                    uint16_t public_key_sz,
                    vs_hsm_hash_type_e hash_type,
                    const uint8_t *hash,
                    const uint8_t *signature,
                    uint16_t signature_sz) {
#define MAX_INT_SIGN_SIZE 256
    uint8_t int_sign[MAX_INT_SIGN_SIZE];
    uint16_t int_sign_sz = sizeof(int_sign);
    vscf_impl_t *pubkey = NULL;
    vscf_alg_id_t hash_id = vscf_alg_id_NONE;
    uint16_t hash_sz = 0;
    vs_status_e res = VS_CODE_ERR_CRYPTO;

    CHECK_NOT_ZERO_RET(public_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(public_key_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    BOOL_CHECK(vs_converters_raw_sign_to_mbedtls(
            keypair_type, signature, signature_sz, int_sign, int_sign_sz, &int_sign_sz),
               "Unable to convert Virgil signature format to the raw one");

    VS_LOG_DEBUG("Internal signature size : %d bytes", int_sign_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Internal signature : ", int_sign, int_sign_sz);

    STATUS_CHECK(_create_pubkey_ctx(keypair_type, public_key, public_key_sz, &pubkey), "Unable to create public key");

    res = VS_CODE_ERR_CRYPTO;

    BOOL_CHECK(_set_hash_info(hash_type, &hash_id, &hash_sz), "Unable to set hash info");

    BOOL_CHECK(vscf_verify_hash(pubkey, vsc_data(hash, hash_sz), hash_id, vsc_data(int_sign, int_sign_sz)),
               "Unable to verify signature");

    res = VS_CODE_OK;

    terminate:

    vscf_impl_delete(pubkey);

    return res;

#undef MAX_INT_SIGN_SIZE
}

/********************************************************************************/
vs_status_e
vs_hsm_hmac(vs_hsm_hash_type_e hash_type,
            const uint8_t *key,
            uint16_t key_sz,
            const uint8_t *input,
            uint16_t input_sz,
            uint8_t *output,
            uint16_t output_buf_sz,
            uint16_t *output_sz) {

    vscf_impl_t *hash_impl;
    vsc_buffer_t out_buf;
    int hash_sz;

    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(input, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    hash_sz = vs_hsm_get_hash_len(hash_type);
    CHECK_RET(hash_sz >= 0, VS_CODE_ERR_CRYPTO, "Unsupported hash type %d", hash_type);
    CHECK_RET(output_buf_sz >= hash_sz, VS_CODE_ERR_TOO_SMALL_BUFFER, "Output buffer too small");

    vscf_hmac_t *hmac = vscf_hmac_new();

    switch (hash_type) {
        case VS_HASH_SHA_256:
            hash_impl = vscf_sha256_impl(vscf_sha256_new());
            break;

        case VS_HASH_SHA_384:
            hash_impl = vscf_sha384_impl(vscf_sha384_new());
            break;

        case VS_HASH_SHA_512:
            hash_impl = vscf_sha512_impl(vscf_sha512_new());
            break;

        default:
            VS_LOG_ERROR("HASH key type %d is not implemented", hash_type);
                    VS_IOT_ASSERT(false);
            return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    vscf_hmac_take_hash(hmac, hash_impl);

    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, output, output_buf_sz);

    vscf_hmac_mac(hmac, vsc_data(key, key_sz), vsc_data(input, input_sz), &out_buf);

    *output_sz = (uint16_t)hash_sz;
    vscf_hmac_delete(hmac);

    return VS_CODE_OK;
}

/********************************************************************************/
vs_status_e
vs_hsm_kdf(vs_hsm_kdf_type_e kdf_type,
           vs_hsm_hash_type_e hash_type,
           const uint8_t *input,
           uint16_t input_sz,
           uint8_t *output,
           uint16_t output_sz) {

    vscf_kdf2_t *kdf2;
    vscf_impl_t *hash_impl;
    vsc_buffer_t out_buf;

    CHECK_NOT_ZERO_RET(input, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(kdf_type == VS_KDF_2, VS_CODE_ERR_NOT_IMPLEMENTED, "KDF type %d is not implemented", kdf_type);

    kdf2 = vscf_kdf2_new();

    switch (hash_type) {
        case VS_HASH_SHA_256:
            hash_impl = vscf_sha256_impl(vscf_sha256_new());
            break;

        case VS_HASH_SHA_384:
            hash_impl = vscf_sha384_impl(vscf_sha384_new());
            break;

        case VS_HASH_SHA_512:
            hash_impl = vscf_sha512_impl(vscf_sha512_new());
            break;

        default:
            VS_LOG_ERROR("HASH key type %d is not implemented", hash_type);
                    VS_IOT_ASSERT(false);
            return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, output, output_sz);
    vscf_kdf2_take_hash(kdf2, hash_impl);
    vscf_kdf2_derive(kdf2, vsc_data(input, input_sz), output_sz, &out_buf);

    vscf_kdf2_delete(kdf2);
    return VS_CODE_OK;
}

/********************************************************************************/
vs_status_e
vs_hsm_hkdf(vs_hsm_hash_type_e hash_type,
            const uint8_t *input,
            uint16_t input_sz,
            const uint8_t *salt,
            uint16_t salt_sz,
            const uint8_t *info,
            uint16_t info_sz,
            uint8_t *output,
            uint16_t output_sz) {

    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
static vscf_impl_t *random_impl = NULL;

static void
destroy_random_impl() {
    vscf_ctr_drbg_delete((vscf_ctr_drbg_t *)random_impl);
}

/********************************************************************************/
vs_status_e
vs_hsm_random(uint8_t *output, uint16_t output_sz) {
    vs_status_e res = VS_CODE_ERR_CRYPTO;
    vsc_buffer_t out_buf;
    uint16_t cur_off = 0;
    uint16_t cur_size = 0;

    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, output, output_sz);

    if (!random_impl) {
        CHECK_MEM_ALLOC(random_impl = (vscf_impl_t *)vscf_ctr_drbg_new(),
                        "Unable to allocate random implementation context");

        atexit(destroy_random_impl);

        CHECK_VSCF(vscf_ctr_drbg_setup_defaults((vscf_ctr_drbg_t *)random_impl),
                   "Unable to initialize random number generator");
    }

    for (cur_off = 0; cur_off < output_sz; cur_off += RNG_MAX_REQUEST) {
        cur_size = output_sz - cur_off;

        if (cur_size > RNG_MAX_REQUEST) {
            cur_size = RNG_MAX_REQUEST;
        }

        CHECK_VSCF(vscf_random(random_impl, cur_size, &out_buf), "Unable to generate random sequence");
    }

    res = VS_CODE_OK;

    terminate:

    if (VS_CODE_OK != res) {
        vsc_buffer_cleanup(&out_buf);
    }

    return res;
}

/********************************************************************************/
static vs_status_e
_aes_gcm_encrypt(const uint8_t *key,
                 uint16_t key_bitlen,
                 const uint8_t *iv,
                 uint16_t iv_len,
                 const uint8_t *add,
                 uint16_t add_len,
                 uint16_t buf_len,
                 const uint8_t *input,
                 uint8_t *output,
                 uint8_t *tag,
                 uint16_t tag_len) {
    uint16_t key_len;
    vsc_buffer_t *out_buf = NULL;
    vsc_buffer_t tag_buf;
    vscf_aes256_gcm_t *aes256_gcm = NULL;
    vs_status_e res = VS_CODE_ERR_CRYPTO;

    CHECK_NOT_ZERO_RET(tag, VS_CODE_ERR_NULLPTR_ARGUMENT);

    key_len = key_bitlen / 8;

    if (key_len != vscf_aes256_gcm_KEY_LEN) {
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    aes256_gcm = vscf_aes256_gcm_new();

    out_buf = vsc_buffer_new_with_capacity(vscf_aes256_gcm_encrypted_len(aes256_gcm, buf_len));
    vsc_buffer_init(&tag_buf);
    vsc_buffer_use(&tag_buf, tag, tag_len);


    vscf_aes256_gcm_set_key(aes256_gcm, vsc_data(key, key_len));
    vscf_aes256_gcm_set_nonce(aes256_gcm, vsc_data(iv, iv_len));

    if (vscf_status_SUCCESS ==
        vscf_aes256_gcm_auth_encrypt(aes256_gcm, vsc_data(input, buf_len), vsc_data(add, add_len), out_buf, &tag_buf)) {
        res = VS_CODE_OK;
        memcpy(output, vsc_buffer_bytes(out_buf), buf_len);
    }

    vscf_aes256_gcm_delete(aes256_gcm);
    vsc_buffer_delete(out_buf);

    return res;
}

/********************************************************************************/
static vs_status_e
_aes_cbc_encrypt(const uint8_t *key,
                 uint16_t key_bitlen,
                 const uint8_t *iv,
                 uint16_t iv_len,
                 uint16_t buf_len,
                 const uint8_t *input,
                 uint8_t *output) {

    uint16_t key_len;
    vsc_buffer_t *out_buf = NULL;
    vscf_aes256_cbc_t *aes256_cbc = NULL;
    vs_status_e res = VS_CODE_ERR_CRYPTO;

    key_len = key_bitlen / 8;

    if (key_len != vscf_aes256_gcm_KEY_LEN) {
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    aes256_cbc = vscf_aes256_cbc_new();

    out_buf = vsc_buffer_new_with_capacity(vscf_aes256_cbc_encrypted_len(aes256_cbc, buf_len));

    vscf_aes256_cbc_set_key(aes256_cbc, vsc_data(key, key_len));
    vscf_aes256_cbc_set_nonce(aes256_cbc, vsc_data(iv, iv_len));

    if (vscf_status_SUCCESS == vscf_aes256_cbc_encrypt(aes256_cbc, vsc_data(input, buf_len), out_buf)) {
        res = VS_CODE_OK;
        memcpy(output, vsc_buffer_bytes(out_buf), vsc_buffer_len(out_buf));
    }

    vscf_aes256_cbc_delete(aes256_cbc);
    vsc_buffer_delete(out_buf);
    return res;
}

/********************************************************************************/
vs_status_e
vs_hsm_aes_encrypt(vs_iot_aes_type_e aes_type,
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
                   uint16_t tag_len) {

    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(iv, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(input, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);

    switch (aes_type) {
        case VS_AES_GCM:
            return _aes_gcm_encrypt(key, key_bitlen, iv, iv_len, add, add_len, buf_len, input, output, tag, tag_len);
        case VS_AES_CBC:
            return _aes_cbc_encrypt(key, key_bitlen, iv, iv_len, buf_len, input, output);
        default:
                    VS_IOT_ASSERT(false);
            return VS_CODE_ERR_NOT_IMPLEMENTED;
    }
}

/********************************************************************************/
static vs_status_e
_aes_cbc_decrypt(const uint8_t *key,
                 uint16_t key_bitlen,
                 const uint8_t *iv,
                 uint16_t iv_len,
                 uint16_t buf_len,
                 const uint8_t *input,
                 uint8_t *output) {
    uint16_t key_len;
    vsc_buffer_t *out_buf = NULL;
    vscf_aes256_cbc_t *aes256_cbc = NULL;
    vs_status_e res = VS_CODE_ERR_CRYPTO;

    key_len = key_bitlen / 8;

    if (key_len != vscf_aes256_gcm_KEY_LEN) {
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    aes256_cbc = vscf_aes256_cbc_new();

    out_buf = vsc_buffer_new_with_capacity(vscf_aes256_cbc_decrypted_len(aes256_cbc, buf_len));

    vscf_aes256_cbc_set_key(aes256_cbc, vsc_data(key, key_len));
    vscf_aes256_cbc_set_nonce(aes256_cbc, vsc_data(iv, iv_len));

    if (vscf_status_SUCCESS == vscf_aes256_cbc_decrypt(aes256_cbc, vsc_data(input, buf_len), out_buf)) {
        res = VS_CODE_OK;
        memcpy(output, vsc_buffer_bytes(out_buf), vsc_buffer_len(out_buf));
    }

    vscf_aes256_cbc_delete(aes256_cbc);
    vsc_buffer_delete(out_buf);

    return res;
}


/********************************************************************************/
vs_status_e
vs_hsm_aes_decrypt(vs_iot_aes_type_e aes_type,
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
                   uint16_t tag_len) {

    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(iv, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(input, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);

    switch (aes_type) {
        case VS_AES_CBC:
            return _aes_cbc_decrypt(key, key_bitlen, iv, iv_len, buf_len, input, output);
        default:
                    VS_IOT_ASSERT(false);
            return VS_CODE_ERR_NOT_IMPLEMENTED;
    }
}

/********************************************************************************/
vs_status_e
vs_hsm_aes_auth_decrypt(vs_iot_aes_type_e aes_type,
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
                        uint16_t tag_len) {

    uint16_t key_len;
    uint8_t add_data = 0;
    vsc_buffer_t *out_buf = NULL;
    vscf_aes256_gcm_t *aes256_gcm = NULL;
    vs_status_e res = VS_CODE_ERR_CRYPTO;

    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(iv, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(input, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(tag, VS_CODE_ERR_NULLPTR_ARGUMENT);

    if (add_len) {
        CHECK_NOT_ZERO_RET(add, VS_CODE_ERR_NULLPTR_ARGUMENT);
    }

    if (NULL == add) {
        add = &add_data;
    }

    key_len = key_bitlen / 8;

    if (VS_AES_GCM != aes_type || key_len != vscf_aes256_gcm_KEY_LEN) {
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    aes256_gcm = vscf_aes256_gcm_new();

    out_buf = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, buf_len));

    vscf_aes256_gcm_set_key(aes256_gcm, vsc_data(key, key_len));
    vscf_aes256_gcm_set_nonce(aes256_gcm, vsc_data(iv, iv_len));

    if (vscf_status_SUCCESS ==
        vscf_aes256_gcm_auth_decrypt(
                aes256_gcm, vsc_data(input, buf_len), vsc_data(add, add_len), vsc_data(tag, tag_len), out_buf)) {
        res = VS_CODE_OK;
        memcpy(output, vsc_buffer_bytes(out_buf), buf_len);
    }

    vscf_aes256_gcm_delete(aes256_gcm);
    vsc_buffer_delete(out_buf);

    return res;
}

/********************************************************************************/
vs_status_e
vs_hsm_ecdh(vs_iot_hsm_slot_e slot,
            vs_hsm_keypair_type_e keypair_type,
            const uint8_t *public_key,
            uint16_t public_key_sz,
            uint8_t *shared_secret,
            uint16_t buf_sz,
            uint16_t *shared_secret_sz) {
    vscf_impl_t *prvkey = NULL;
    vscf_impl_t *pubkey = NULL;
    vsc_buffer_t out_buf;
    size_t required_sz;
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(public_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(shared_secret, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(shared_secret_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(_load_prvkey(slot, &prvkey, &keypair_type),
                     "Unable to load private key from slot %d (%s)",
                     slot,
                     get_slot_name((slot)));

    if ((required_sz = vscf_compute_shared_key_shared_key_len(prvkey)) > buf_sz) {
        VS_LOG_ERROR("Output buffer too small");
        ret_code = VS_CODE_ERR_TOO_SMALL_BUFFER;
        goto terminate;
    }
    *shared_secret_sz = (uint16_t)required_sz;

    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, shared_secret, buf_sz);

    ret_code = _create_pubkey_ctx(keypair_type, public_key, public_key_sz, &pubkey);

    if (VS_CODE_OK == ret_code) {
        ret_code = (vscf_status_SUCCESS == vscf_compute_shared_key(prvkey, pubkey, &out_buf)) ? VS_CODE_OK
                                                                                              : VS_CODE_ERR_CRYPTO;
    }

    terminate:
    vscf_impl_delete(prvkey);
    vscf_impl_delete(pubkey);
    return ret_code;
}

/********************************************************************************/
static vs_status_e
vs_hsm_secp256r1_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_secp256r1_private_key_t *prvkey_ctx = NULL;
    vscf_secp256r1_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    VS_LOG_DEBUG(
            "Generate keypair %s and save it to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(prvkey_ctx = vscf_secp256r1_private_key_new(),
                    "Unable to allocate memory for slot %s",
                    get_slot_name(slot));

    CHECK_VSCF(vscf_secp256r1_private_key_setup_defaults(prvkey_ctx),
               "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_secp256r1_private_key_generate_key(prvkey_ctx), "Unable to generate private key");

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    ADD_KEYTYPE(buf, keypair_buf, keypair_type);

    key_sz = vscf_secp256r1_private_key_exported_private_key_len(prvkey_ctx);
    ADD_PRVKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_secp256r1_private_key_export_private_key(prvkey_ctx, &keypair_buf), "Unable to export private key");

    LOG_PRVKEY(buf);

    CHECK_MEM_ALLOC(pubkey_ctx =
                            (vscf_secp256r1_public_key_t *)vscf_secp256r1_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory");

    key_sz = vscf_secp256r1_public_key_exported_public_key_len(pubkey_ctx);
    ADD_PUBKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_secp256r1_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    LOG_PUBKEY(buf);

    STATUS_CHECK(vs_hsm_slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
                 "Unable to save keypair buffer to the slot %s",
                 get_slot_name(slot));

    ret_code = VS_CODE_OK;

    terminate:

    if (prvkey_ctx) {
        vscf_secp256r1_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_secp256r1_public_key_delete(pubkey_ctx);
    }

    return ret_code;
}

/********************************************************************************/
static vs_status_e
vs_hsm_curve25519_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_curve25519_private_key_t *prvkey_ctx = NULL;
    vscf_curve25519_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    VS_LOG_DEBUG(
            "Generate keypair %s and save it to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(prvkey_ctx = vscf_curve25519_private_key_new(),
                    "Unable to allocate memory for slot %s",
                    get_slot_name(slot));

    CHECK_VSCF(vscf_curve25519_private_key_setup_defaults(prvkey_ctx),
               "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_curve25519_private_key_generate_key(prvkey_ctx), "Unable to generate private key");

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    ADD_KEYTYPE(buf, keypair_buf, keypair_type);

    key_sz = vscf_curve25519_private_key_exported_private_key_len(prvkey_ctx);
    ADD_PRVKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_curve25519_private_key_export_private_key(prvkey_ctx, &keypair_buf),
               "Unable to export private key");

    LOG_PRVKEY(buf);

    CHECK_MEM_ALLOC(pubkey_ctx =
                            (vscf_curve25519_public_key_t *)vscf_curve25519_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory");

    key_sz = vscf_curve25519_public_key_exported_public_key_len(pubkey_ctx);
    ADD_PUBKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_curve25519_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    LOG_PUBKEY(buf);

    STATUS_CHECK(vs_hsm_slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
                 "Unable to save keypair buffer to the slot %s",
                 get_slot_name(slot));

    ret_code = VS_CODE_OK;

    terminate:

    if (prvkey_ctx) {
        vscf_curve25519_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_curve25519_public_key_delete(pubkey_ctx);
    }

    return ret_code;
}

/********************************************************************************/
static vs_status_e
vs_hsm_ed25519_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_ed25519_private_key_t *prvkey_ctx = NULL;
    vscf_ed25519_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    VS_LOG_DEBUG(
            "Generate keypair %s and save it to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(
            prvkey_ctx = vscf_ed25519_private_key_new(), "Unable to allocate memory for slot %s", get_slot_name(slot));

    CHECK_VSCF(vscf_ed25519_private_key_setup_defaults(prvkey_ctx),
               "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_ed25519_private_key_generate_key(prvkey_ctx), "Unable to generate private key");

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    ADD_KEYTYPE(buf, keypair_buf, keypair_type);

    key_sz = vscf_ed25519_private_key_exported_private_key_len(prvkey_ctx);
    ADD_PRVKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_ed25519_private_key_export_private_key(prvkey_ctx, &keypair_buf), "Unable to export private key");

    LOG_PRVKEY(buf);

    CHECK_MEM_ALLOC(pubkey_ctx = (vscf_ed25519_public_key_t *)vscf_ed25519_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory");

    key_sz = vscf_ed25519_public_key_exported_public_key_len(pubkey_ctx);
    ADD_PUBKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_ed25519_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    LOG_PUBKEY(buf);

    STATUS_CHECK(vs_hsm_slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
                 "Unable to save keypair buffer to the slot %s",
                 get_slot_name(slot));

    ret_code = VS_CODE_OK;

    terminate:

    if (prvkey_ctx) {
        vscf_ed25519_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_ed25519_public_key_delete(pubkey_ctx);
    }

    return ret_code;
}

/********************************************************************************/
static vs_status_e
vs_hsm_rsa_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_rsa_private_key_t *prvkey_ctx = NULL;
    vscf_rsa_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    VS_LOG_DEBUG(
            "Generate keypair %s and save it to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(
            prvkey_ctx = vscf_rsa_private_key_new(), "Unable to allocate memory for slot %s", get_slot_name(slot));

    CHECK_VSCF(vscf_rsa_private_key_setup_defaults(prvkey_ctx), "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_rsa_private_key_generate_key(prvkey_ctx), "Unable to generate private key");

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    ADD_KEYTYPE(buf, keypair_buf, keypair_type);

    key_sz = vscf_rsa_private_key_exported_private_key_len(prvkey_ctx);
    ADD_PRVKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_rsa_private_key_export_private_key(prvkey_ctx, &keypair_buf), "Unable to export private key");

    LOG_PRVKEY(buf);

    CHECK_MEM_ALLOC(pubkey_ctx = (vscf_rsa_public_key_t *)vscf_rsa_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory");

    key_sz = vscf_rsa_public_key_exported_public_key_len(pubkey_ctx);
    ADD_PUBKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_rsa_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    LOG_PUBKEY(buf);

    STATUS_CHECK_RET(vs_hsm_slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
                     "Unable to save keypair buffer to the slot %s",
                     get_slot_name(slot));

    ret_code = VS_CODE_OK;

    terminate:

    if (prvkey_ctx) {
        vscf_rsa_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_rsa_public_key_delete(pubkey_ctx);
    }

    return ret_code;
}

/********************************************************************************/
vs_status_e
vs_hsm_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    switch (keypair_type) {
        case VS_KEYPAIR_EC_SECP256R1:
            return vs_hsm_secp256r1_keypair_create(slot, keypair_type);

        case VS_KEYPAIR_EC_CURVE25519:
            return vs_hsm_curve25519_keypair_create(slot, keypair_type);

        case VS_KEYPAIR_EC_ED25519:
            return vs_hsm_ed25519_keypair_create(slot, keypair_type);

        case VS_KEYPAIR_RSA_2048:
            return vs_hsm_rsa_keypair_create(slot, keypair_type);

        default:
            VS_LOG_WARNING("Unsupported keypair type %s", vs_hsm_keypair_type_descr(keypair_type));
            return VS_CODE_ERR_NOT_IMPLEMENTED;
    }
}

/********************************************************************************/
vs_status_e
vs_hsm_keypair_get_pubkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type) {
    uint8_t keypair_buf[KEYPAIR_BUF_SZ];
    uint16_t keypair_buf_sz = sizeof(keypair_buf);
    uint8_t pubkey_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    STATUS_CHECK_RET(vs_hsm_slot_load(slot, keypair_buf, keypair_buf_sz, &keypair_buf_sz),
                     "Unable to load data from slot %d (%s)",
                     slot,
                     get_slot_name(slot));

    pubkey_sz = keypair_buf[KEYPAIR_BUF_PUBKEYSZ_OFF(keypair_buf)];
    if (pubkey_sz == 0) {
        VS_LOG_ERROR("Zero size public key");
        goto terminate;
    }
    if (pubkey_sz > buf_sz) {
        VS_LOG_ERROR("Too big public key size %d bytes for buffer %d bytes", pubkey_sz, buf_sz);
        goto terminate;
    }

    memcpy(buf, keypair_buf + KEYPAIR_BUF_PUBKEY_OFF(keypair_buf), pubkey_sz);
    *key_sz = pubkey_sz;

    *keypair_type = keypair_buf[KEYPAIR_BUF_KEYTYPE_OFF];

    VS_LOG_DEBUG("Public key %d bytes from slot %s with keypair type %s has been loaded",
                 pubkey_sz,
                 get_slot_name(slot),
                 vs_hsm_keypair_type_descr(*keypair_type));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Public key : ", buf, *key_sz);

    ret_code = VS_CODE_OK;

    terminate:

    return ret_code;
}

/********************************************************************************/
vs_status_e
vs_hsm_keypair_get_prvkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type) {
    uint8_t keypair_buf[KEYPAIR_BUF_SZ];
    uint16_t keypair_buf_sz = sizeof(keypair_buf);
    uint8_t prvkey_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    STATUS_CHECK_RET(vs_hsm_slot_load(slot, keypair_buf, keypair_buf_sz, &keypair_buf_sz),
                     "Unable to load data from slot %d (%s)",
                     slot,
                     get_slot_name(slot));

    prvkey_sz = keypair_buf[KEYPAIR_BUF_PRVKEYSZ_OFF];
    if (prvkey_sz == 0) {
        VS_LOG_ERROR("Zero size private key");
        goto terminate;
    }
    if (prvkey_sz > buf_sz) {
        VS_LOG_ERROR("Too big private key %d bytes for buffer %d bytes", prvkey_sz, buf_sz);
        goto terminate;
    }

    memcpy(buf, keypair_buf + KEYPAIR_BUF_PRVKEY_OFF, prvkey_sz);
    *key_sz = prvkey_sz;

    *keypair_type = keypair_buf[KEYPAIR_BUF_KEYTYPE_OFF];

    VS_LOG_DEBUG("Private key %d bytes from slot %s with keypair type %s has been loaded",
                 prvkey_sz,
                 get_slot_name(slot),
                 vs_hsm_keypair_type_descr(*keypair_type));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Private key : ", buf, *key_sz);

    ret_code = VS_CODE_OK;

    terminate:

    return ret_code;
}

/********************************************************************************/
vs_status_e
vs_hsm_slot_save(vs_iot_hsm_slot_e slot, const uint8_t *data, uint16_t data_sz) {
    return vs_nix_write_file_data(slots_dir, get_slot_name(slot), 0, data, data_sz) &&
           vs_nix_sync_file(slots_dir, get_slot_name(slot))
           ? VS_CODE_OK
           : VS_CODE_ERR_FILE_WRITE;
}

/********************************************************************************/
vs_status_e
vs_hsm_slot_load(vs_iot_hsm_slot_e slot, uint8_t *data, uint16_t buf_sz, uint16_t *out_sz) {
    size_t out_sz_size_t = *out_sz;
    vs_status_e call_res;

    call_res = vs_nix_read_file_data(slots_dir, get_slot_name(slot), 0, data, buf_sz, &out_sz_size_t)
               ? VS_CODE_OK
               : VS_CODE_ERR_FILE_READ;

    assert(out_sz_size_t <= UINT16_MAX);
    *out_sz = out_sz_size_t;

    return call_res;
}

/******************************************************************************/
vs_status_e
vs_hsm_slot_delete(vs_iot_hsm_slot_e slot) {
    return vs_nix_remove_file_data(slots_dir, get_slot_name(slot)) ? VS_CODE_OK : VS_CODE_ERR_FILE_DELETE;
}

/********************************************************************************/
const char *
vs_nix_get_slots_dir() {
    return slots_dir;
}

/******************************************************************************/
const char *
get_slot_name(vs_iot_hsm_slot_e slot) {
    switch (slot) {
        case VS_KEY_SLOT_STD_OTP_0:
            return "STD_OTP_0";
        case VS_KEY_SLOT_STD_OTP_1:
            return "STD_OTP_1";
        case VS_KEY_SLOT_STD_OTP_2:
            return "STD_OTP_2";
        case VS_KEY_SLOT_STD_OTP_3:
            return "STD_OTP_3";
        case VS_KEY_SLOT_STD_OTP_4:
            return "STD_OTP_4";
        case VS_KEY_SLOT_STD_OTP_5:
            return "STD_OTP_5";
        case VS_KEY_SLOT_STD_OTP_6:
            return "STD_OTP_6";
        case VS_KEY_SLOT_STD_OTP_7:
            return "STD_OTP_7";
        case VS_KEY_SLOT_STD_OTP_8:
            return "STD_OTP_8";
        case VS_KEY_SLOT_STD_OTP_9:
            return "STD_OTP_9";
        case VS_KEY_SLOT_STD_OTP_10:
            return "STD_OTP_10";
        case VS_KEY_SLOT_STD_OTP_11:
            return "STD_OTP_11";
        case VS_KEY_SLOT_STD_OTP_12:
            return "STD_OTP_12";
        case VS_KEY_SLOT_STD_OTP_13:
            return "STD_OTP_13";
        case VS_KEY_SLOT_STD_OTP_14:
            return "STD_OTP_14";
        case VS_KEY_SLOT_EXT_OTP_0:
            return "EXT_OTP_0";
        case VS_KEY_SLOT_STD_MTP_0:
            return "STD_MTP_0";
        case VS_KEY_SLOT_STD_MTP_1:
            return "STD_MTP_1";
        case VS_KEY_SLOT_STD_MTP_2:
            return "STD_MTP_2";
        case VS_KEY_SLOT_STD_MTP_3:
            return "STD_MTP_3";
        case VS_KEY_SLOT_STD_MTP_4:
            return "STD_MTP_4";
        case VS_KEY_SLOT_STD_MTP_5:
            return "STD_MTP_5";
        case VS_KEY_SLOT_STD_MTP_6:
            return "STD_MTP_6";
        case VS_KEY_SLOT_STD_MTP_7:
            return "STD_MTP_7";
        case VS_KEY_SLOT_STD_MTP_8:
            return "STD_MTP_8";
        case VS_KEY_SLOT_STD_MTP_9:
            return "STD_MTP_9";
        case VS_KEY_SLOT_STD_MTP_10:
            return "STD_MTP_10";
        case VS_KEY_SLOT_STD_MTP_11:
            return "STD_MTP_11";
        case VS_KEY_SLOT_STD_MTP_12:
            return "STD_MTP_12";
        case VS_KEY_SLOT_STD_MTP_13:
            return "STD_MTP_13";
        case VS_KEY_SLOT_STD_MTP_14:
            return "STD_MTP_14";
        case VS_KEY_SLOT_EXT_MTP_0:
            return "EXT_MTP_0";
        case VS_KEY_SLOT_STD_TMP_0:
            return "STD_TMP_0";
        case VS_KEY_SLOT_STD_TMP_1:
            return "STD_TMP_1";
        case VS_KEY_SLOT_STD_TMP_2:
            return "STD_TMP_2";
        case VS_KEY_SLOT_STD_TMP_3:
            return "STD_TMP_3";
        case VS_KEY_SLOT_STD_TMP_4:
            return "STD_TMP_4";
        case VS_KEY_SLOT_STD_TMP_5:
            return "STD_TMP_5";
        case VS_KEY_SLOT_STD_TMP_6:
            return "STD_TMP_6";
        case VS_KEY_SLOT_EXT_TMP_0:
            return "EXT_TMP_0";

        default:
            assert(false && "Unsupported slot");
            return NULL;
    }
}
