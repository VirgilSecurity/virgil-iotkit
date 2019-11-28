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

#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include <mbedtls/kdf.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk_internal.h>

#include "private/vs-soft-secmodule-internal.h"

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/converters/crypto_format_converters.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/status_code/status_code.h>

#define RNG_MAX_REQUEST (256)
#define MAX_INTERNAL_SIGN_SIZE (180)
#define MAX_INTERNAL_PUBKEY_SIZE (180)
/********************************************************************************/
static vs_status_e
vs_secmodule_hash_create(vs_secmodule_hash_type_e hash_type,
                         const uint8_t *data,
                         uint16_t data_sz,
                         uint8_t *hash,
                         uint16_t hash_buf_sz,
                         uint16_t *hash_sz) {

    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    vs_status_e res = VS_CODE_OK;

    switch (hash_type) {
    case VS_HASH_SHA_256:
        *hash_sz = VS_HASH_SHA256_LEN;
        mbedtls_sha256(data, data_sz, hash, 0);
        break;

    case VS_HASH_SHA_384:
        *hash_sz = VS_HASH_SHA384_LEN;
        mbedtls_sha512(data, data_sz, hash, 1);
        break;

    case VS_HASH_SHA_512:
        *hash_sz = VS_HASH_SHA512_LEN;
        mbedtls_sha512(data, data_sz, hash, 0);
        break;

    default:
        assert(false && "Unsupported hash type");
        VS_LOG_ERROR("Unsupported hash type");
        res = VS_CODE_ERR_NOT_IMPLEMENTED;
        break;
    }

    return res;
}

/********************************************************************************/
static mbedtls_md_type_t
_hash_to_mbedtls(vs_secmodule_hash_type_e hash_type) {
    switch (hash_type) {
    case VS_HASH_SHA_256:
        return MBEDTLS_MD_SHA256;
    case VS_HASH_SHA_384:
        return MBEDTLS_MD_SHA384;
    case VS_HASH_SHA_512:
        return MBEDTLS_MD_SHA512;
    default:
        return MBEDTLS_MD_NONE;
    }
}

/********************************************************************************/
static bool
_create_context_for_private_key(mbedtls_pk_context *ctx, const uint8_t *private_key, size_t private_key_sz) {
    mbedtls_pk_context res;
    mbedtls_pk_init(&res);

    if (0 == mbedtls_pk_parse_key(&res, (const unsigned char *)private_key, private_key_sz, NULL, 0)) {
        *ctx = res;
        return true;
    }
    return false;
}

/********************************************************************************/
static bool
_create_context_for_public_key(mbedtls_pk_context *ctx,
                               vs_secmodule_keypair_type_e keypair_type,
                               const uint8_t *public_key,
                               size_t public_key_sz) {
    mbedtls_pk_context res;
    mbedtls_pk_init(&res);

    uint8_t internal_key[MAX_INTERNAL_PUBKEY_SIZE];
    uint8_t *p_internal_key;
    uint16_t internal_key_sz = 0;

    if (vs_converters_pubkey_to_virgil(
                keypair_type, public_key, public_key_sz, internal_key, sizeof(internal_key), &internal_key_sz)) {
        p_internal_key = (unsigned char *)internal_key;
    } else {
        return false;
    }

    if (0 == mbedtls_pk_parse_public_key(&res, p_internal_key, internal_key_sz)) {
        *ctx = res;
        return true;
    }
    return false;
}

/********************************************************************************/
static vs_status_e
vs_secmodule_ecdsa_sign(vs_iot_secmodule_slot_e key_slot,
                        vs_secmodule_hash_type_e hash_type,
                        const uint8_t *hash,
                        uint8_t *signature,
                        uint16_t signature_buf_sz,
                        uint16_t *signature_sz) {

    vs_status_e ret_code;
    vs_secmodule_keypair_type_e keypair_type;
    int32_t slot_sz = _get_slot_size(key_slot);
    uint16_t private_key_sz;
    size_t sign_len;
    const char *pers = "sign";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context private_key_ctx;

    CHECK_RET(slot_sz > 0, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect slot number");
    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_buf_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    uint8_t private_key[slot_sz];
    uint8_t internal_sign[MAX_INTERNAL_SIGN_SIZE];

    STATUS_CHECK_RET(vs_secmodule_keypair_get_prvkey(key_slot, private_key, slot_sz, &private_key_sz, &keypair_type),
                     "Unable to load private key data from slot %s",
                     _get_slot_name(key_slot));
    ret_code = VS_CODE_ERR_CRYPTO;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&private_key_ctx);

    if (_create_context_for_private_key(&private_key_ctx, private_key, private_key_sz) &&
        0 == mbedtls_ctr_drbg_seed(
                     &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) &&
        0 == mbedtls_pk_sign(&private_key_ctx,
                             _hash_to_mbedtls(hash_type),
                             hash,
                             0,
                             internal_sign,
                             &sign_len,
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg) &&
        sign_len <= UINT16_MAX) {
        ret_code = VS_CODE_OK;
    }

    if (!vs_converters_mbedtls_sign_to_raw(
                keypair_type, internal_sign, sign_len, signature, signature_buf_sz, signature_sz)) {
        ret_code = VS_CODE_ERR_CRYPTO;
    }

#if 0
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

    CHECK(_set_hash_info(hash_type, &hash_id, &hash_sz), "Unable to set hash info");

    CHECK(VS_CODE_OK == _load_prvkey(key_slot, &prvkey, &keypair_type),
          "Unable to load private key from slot %d (%s)",
          key_slot,
          get_slot_name((key_slot)));

    required_sign_sz = vscf_sign_hash_signature_len(prvkey);

    vsc_buffer_alloc(&sign_data, required_sign_sz);

    CHECK_VSCF(vscf_sign_hash(prvkey, vsc_data(hash, hash_sz), hash_id, &sign_data), "Unable to sign data");

    *signature_sz = vsc_buffer_len(&sign_data);

    VS_LOG_DEBUG("Internal signature size : %d bytes", *signature_sz);

    CHECK(vs_converters_mbedtls_sign_to_raw(
                  keypair_type, vsc_buffer_begin(&sign_data), *signature_sz, signature, signature_buf_sz, signature_sz),
          "Unable to convert Virgil signature format to the raw one");

    VS_LOG_DEBUG("Output signature size : %d bytes", *signature_sz);

    res = VS_CODE_OK;

terminate:
    vsc_buffer_release(&sign_data);

    if (prvkey) {
        vscf_impl_destroy(&prvkey);
    }

    return res;
#endif
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&private_key_ctx);

    return ret_code;
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
    mbedtls_pk_context public_key_ctx;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;
    uint8_t internal_sign[MAX_INTERNAL_SIGN_SIZE];

    CHECK_NOT_ZERO_RET(public_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(public_key_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    mbedtls_pk_init(&public_key_ctx);

    if (_create_context_for_public_key(&public_key_ctx, keypair_type, public_key, public_key_sz) &&
        vs_converters_raw_sign_to_mbedtls(
                keypair_type, signature, signature_sz, internal_sign, sizeof(internal_sign), &signature_sz) &&
        0 == mbedtls_pk_verify(&public_key_ctx, _hash_to_mbedtls(hash_type), hash, 0, internal_sign, signature_sz)) {
        ret_code = VS_CODE_OK;
    }

    mbedtls_pk_free(&public_key_ctx);
#if 0
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

    CHECK(vs_converters_raw_sign_to_mbedtls(keypair_type, signature, signature_sz, int_sign, int_sign_sz, &int_sign_sz),
          "Unable to convert Virgil signature format to the raw one");

    VS_LOG_DEBUG("Internal signature size : %d bytes", int_sign_sz);

    STATUS_CHECK(_create_pubkey_ctx(keypair_type, public_key, public_key_sz, &pubkey), "Unable to create public key");

    res = VS_CODE_ERR_CRYPTO;

    CHECK(_set_hash_info(hash_type, &hash_id, &hash_sz), "Unable to set hash info");

    CHECK(vscf_verify_hash(pubkey, vsc_data(hash, hash_sz), hash_id, vsc_data(int_sign, int_sign_sz)),
          "Unable to verify signature");

    res = VS_CODE_OK;

terminate:

    vscf_impl_delete(pubkey);

    return res;

#undef MAX_INT_SIGN_SIZE
#endif
    return ret_code;
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
    int hash_sz;

    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(input, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    hash_sz = vs_secmodule_get_hash_len(hash_type);
    CHECK_RET(hash_sz >= 0, VS_CODE_ERR_CRYPTO, "Unsupported hash type %d", hash_type);
    CHECK_RET(output_buf_sz >= hash_sz, VS_CODE_ERR_TOO_SMALL_BUFFER, "Output buffer too small");

    *output_sz = (uint16_t)hash_sz;
    return (0 == mbedtls_md_hmac(mbedtls_md_info_from_type(_hash_to_mbedtls(hash_type)),
                                 (const unsigned char *)key,
                                 key_sz,
                                 (const unsigned char *)input,
                                 input_sz,
                                 (unsigned char *)output))
                   ? VS_CODE_OK
                   : VS_CODE_ERR_CRYPTO;
}

/********************************************************************************/
static vs_status_e
vs_secmodule_kdf(vs_secmodule_kdf_type_e kdf_type,
                 vs_secmodule_hash_type_e hash_type,
                 const uint8_t *input,
                 uint16_t input_sz,
                 uint8_t *output,
                 uint16_t output_sz) {

    CHECK_NOT_ZERO_RET(input, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(kdf_type == VS_KDF_2, VS_CODE_ERR_NOT_IMPLEMENTED, "KDF type %d is not implemented", kdf_type);

    const mbedtls_kdf_info_t *kdf_info = mbedtls_kdf_info_from_type(MBEDTLS_KDF_KDF2);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(_hash_to_mbedtls(hash_type));

    CHECK_RET(kdf_info && md_info, VS_CODE_ERR_CRYPTO, "Error create kdf info");

    return (0 == mbedtls_kdf(kdf_info, md_info, input, input_sz, output, output_sz)) ? VS_CODE_OK : VS_CODE_ERR_CRYPTO;
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
static vs_status_e
vs_secmodule_random(uint8_t *output, uint16_t output_sz) {
    static bool is_init = false;
    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;

    uint16_t cur_off = 0;
    uint16_t cur_size = 0;

    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output_sz, VS_CODE_ERR_INCORRECT_PARAMETER);

    if (!is_init) {
        const char *pers = "gen_random";
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        if (0 != mbedtls_ctr_drbg_seed(
                         &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) {
            VS_LOG_ERROR("Error drbg initialization");
            mbedtls_entropy_free(&entropy);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            return VS_CODE_ERR_CRYPTO;
        }
        is_init = true;
    }

    while (cur_off < output_sz) {
        cur_size = (output_sz - cur_off) > RNG_MAX_REQUEST ? RNG_MAX_REQUEST : (output_sz - cur_off);

        CHECK_RET(0 == mbedtls_ctr_drbg_random(&ctr_drbg, output + cur_off, cur_size),
                  VS_CODE_ERR_CRYPTO,
                  "Unable to generate random sequence");

        cur_off += cur_size;
    }

    return VS_CODE_OK;
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
#if 0
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
#endif
    return VS_CODE_ERR_NOT_IMPLEMENTED;
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

#if 0
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
#endif
    return VS_CODE_ERR_NOT_IMPLEMENTED;
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
#if 0
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
#endif
    return VS_CODE_ERR_NOT_IMPLEMENTED;
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

#if 0
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
#endif
    return VS_CODE_ERR_NOT_IMPLEMENTED;
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
#if 0
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
#endif
    return VS_CODE_ERR_NOT_IMPLEMENTED;
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
