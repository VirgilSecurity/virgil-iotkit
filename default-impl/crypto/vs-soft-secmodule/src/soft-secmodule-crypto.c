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

#include "private/vs-soft-secmodule-internal.h"

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
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

#define RNG_MAX_REQUEST (256)

/********************************************************************************/
static vs_status_e
vs_secmodule_hash_create(vs_secmodule_hash_type_e hash_type,
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

    VS_LOG_DEBUG("Generate hash %s for data size %d", vs_secmodule_hash_type_descr(hash_type), data_sz);

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

    VS_LOG_DEBUG("Hash size %d, type %s", *hash_sz, vs_secmodule_hash_type_descr(hash_type));
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
_load_prvkey(vs_iot_secmodule_slot_e key_slot, vscf_impl_t **prvkey, vs_secmodule_keypair_type_e *keypair_type) {
    uint8_t prvkey_buf[MAX_KEY_SZ];
    uint16_t prvkey_buf_sz = sizeof(prvkey_buf);
    vsc_data_t prvkey_data;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    CHECK_NOT_ZERO_RET(prvkey, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(keypair_type, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(vs_secmodule_keypair_get_prvkey(key_slot, prvkey_buf, prvkey_buf_sz, &prvkey_buf_sz, keypair_type),
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
        VS_LOG_ERROR("Unsupported keypair type %d (%s)", keypair_type, vs_secmodule_keypair_type_descr(*keypair_type));
        ret_code = VS_CODE_ERR_NOT_IMPLEMENTED;
        goto terminate;
    }

    ret_code = VS_CODE_OK;

terminate:

    return ret_code;
}

/********************************************************************************/
static vs_status_e
_create_pubkey_ctx(vs_secmodule_keypair_type_e keypair_type,
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
        VS_LOG_ERROR("Unsupported keypair type %d (%s)", keypair_type, vs_secmodule_keypair_type_descr(keypair_type));
        res = VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    return res;
}

/********************************************************************************/
static bool
_set_hash_info(vs_secmodule_hash_type_e hash_type, vscf_alg_id_t *hash_id, uint16_t *hash_sz) {

    *hash_sz = (uint16_t)vs_secmodule_get_hash_len(hash_type);

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
static vs_status_e
vs_secmodule_ecdsa_sign(vs_iot_secmodule_slot_e key_slot,
                        vs_secmodule_hash_type_e hash_type,
                        const uint8_t *hash,
                        uint8_t *signature,
                        uint16_t signature_buf_sz,
                        uint16_t *signature_sz) {
    vscf_impl_t *prvkey = NULL;
    vscf_alg_id_t hash_id = vscf_alg_id_NONE;
    uint16_t hash_sz = 0;
    vsc_buffer_t sign_data;
    vs_secmodule_keypair_type_e keypair_type = VS_KEYPAIR_INVALID;
    uint16_t required_sign_sz = 0;
    vs_status_e res = VS_CODE_ERR_CRYPTO;

    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    vsc_buffer_init(&sign_data);

    CHECK_BOOL(_set_hash_info(hash_type, &hash_id, &hash_sz), "Unable to set hash info");

    CHECK_BOOL(VS_CODE_OK == _load_prvkey(key_slot, &prvkey, &keypair_type),
               "Unable to load private key from slot %d (%s)",
               key_slot,
               get_slot_name((key_slot)));

    required_sign_sz = vscf_sign_hash_signature_len(prvkey);

    vsc_buffer_alloc(&sign_data, required_sign_sz);

    CHECK_VSCF(vscf_sign_hash(prvkey, vsc_data(hash, hash_sz), hash_id, &sign_data), "Unable to sign data");

    *signature_sz = vsc_buffer_len(&sign_data);

    VS_LOG_DEBUG("Internal signature size : %d bytes", *signature_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Internal signature : ", vsc_buffer_begin(&sign_data), *signature_sz);

    CHECK_BOOL(vs_converters_mbedtls_sign_to_raw(keypair_type,
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
static vs_status_e
vs_secmodule_ecdsa_verify(vs_secmodule_keypair_type_e keypair_type,
                          const uint8_t *public_key,
                          uint16_t public_key_sz,
                          vs_secmodule_hash_type_e hash_type,
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

    CHECK_BOOL(vs_converters_raw_sign_to_mbedtls(
                       keypair_type, signature, signature_sz, int_sign, int_sign_sz, &int_sign_sz),
               "Unable to convert Virgil signature format to the raw one");

    VS_LOG_DEBUG("Internal signature size : %d bytes", int_sign_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Internal signature : ", int_sign, int_sign_sz);

    STATUS_CHECK(_create_pubkey_ctx(keypair_type, public_key, public_key_sz, &pubkey), "Unable to create public key");

    res = VS_CODE_ERR_CRYPTO;

    CHECK_BOOL(_set_hash_info(hash_type, &hash_id, &hash_sz), "Unable to set hash info");

    CHECK_BOOL(vscf_verify_hash(pubkey, vsc_data(hash, hash_sz), hash_id, vsc_data(int_sign, int_sign_sz)),
               "Unable to verify signature");

    res = VS_CODE_OK;

terminate:

    vscf_impl_delete(pubkey);

    return res;

#undef MAX_INT_SIGN_SIZE
}

/********************************************************************************/
static vs_status_e
vs_secmodule_hmac(vs_secmodule_hash_type_e hash_type,
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

    hash_sz = vs_secmodule_get_hash_len(hash_type);
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
static vs_status_e
vs_secmodule_kdf(vs_secmodule_kdf_type_e kdf_type,
                 vs_secmodule_hash_type_e hash_type,
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
static vs_status_e
vs_secmodule_hkdf(vs_secmodule_hash_type_e hash_type,
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
static vs_status_e
vs_secmodule_random(uint8_t *output, uint16_t output_sz) {
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
static vs_status_e
vs_secmodule_aes_encrypt(vs_iot_aes_type_e aes_type,
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
static vs_status_e
vs_secmodule_aes_decrypt(vs_iot_aes_type_e aes_type,
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
static vs_status_e
vs_secmodule_aes_auth_decrypt(vs_iot_aes_type_e aes_type,
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
static vs_status_e
vs_secmodule_ecdh(vs_iot_secmodule_slot_e slot,
                  vs_secmodule_keypair_type_e keypair_type,
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
vs_status_e
_fill_crypto_impl(vs_secmodule_impl_t *secmodule_impl) {

    secmodule_impl->random = vs_secmodule_random;

    secmodule_impl->ecdsa_sign = vs_secmodule_ecdsa_sign;
    secmodule_impl->ecdsa_verify = vs_secmodule_ecdsa_verify;

    secmodule_impl->ecdh = vs_secmodule_ecdh;

    secmodule_impl->aes_encrypt = vs_secmodule_aes_encrypt;
    secmodule_impl->aes_decrypt = vs_secmodule_aes_decrypt;
    secmodule_impl->aes_auth_decrypt = vs_secmodule_aes_auth_decrypt;

    secmodule_impl->hash = vs_secmodule_hash_create;

    secmodule_impl->hmac = vs_secmodule_hmac;

    secmodule_impl->kdf = vs_secmodule_kdf;

    secmodule_impl->hkdf = vs_secmodule_hkdf;

    return VS_CODE_OK;
}

/********************************************************************************/
