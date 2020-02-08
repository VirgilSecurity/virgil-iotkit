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
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <mbedtls/cipher.h>

#include <defaults/vs-soft-secmodule/private/vs-soft-secmodule-internal.h>

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/converters/crypto_format_converters.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/status_code/status_code.h>

#define RNG_MAX_REQUEST (256)

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
        sign_len <= UINT16_MAX &&
        vs_converters_mbedtls_sign_to_raw(
                keypair_type, internal_sign, sign_len, signature, signature_buf_sz, signature_sz)) {
        ret_code = VS_CODE_OK;
    }

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
#define KDF2_TRY(invocation) \
do { \
    result = invocation; \
    if((result) < 0) { \
        goto exit; \
    } \
} while (0)

#define KDF2_CEIL(x,y) (1 + ((x - 1) / y))

static vs_status_e 
_mbedtls_kdf2(const mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
        unsigned char * output, size_t olen)
{
    int result = 0;
    size_t counter = 1;
    size_t counter_len = 0;
    unsigned char counter_string[4] = {0x0};

    unsigned char hash[MBEDTLS_MD_MAX_SIZE] = {0x0};
    unsigned char hash_len = 0;

    size_t olen_actual = 0;

    mbedtls_md_context_t md_ctx;

    CHECK_NOT_ZERO_RET(md_info, VS_CODE_ERR_CRYPTO);

    // Initialize digest context
    mbedtls_md_init(&md_ctx);
    KDF2_TRY(mbedtls_md_setup(&md_ctx, md_info, 0));

    // Get hash parameters
    hash_len = mbedtls_md_get_size(md_info);

    // Get KDF parameters
    counter_len = KDF2_CEIL(olen, hash_len);

    // Start hashing
    for(; counter <= counter_len; ++counter) {
        counter_string[0] = (unsigned char)((counter >> 24) & 255);
        counter_string[1] = (unsigned char)((counter >> 16) & 255);
        counter_string[2] = (unsigned char)((counter >> 8)) & 255;
        counter_string[3] = (unsigned char)(counter & 255);
        KDF2_TRY(mbedtls_md_starts(&md_ctx));
        KDF2_TRY(mbedtls_md_update(&md_ctx, input, ilen));
        KDF2_TRY(mbedtls_md_update(&md_ctx, counter_string, 4));
        if (olen_actual + hash_len <= olen) {
            KDF2_TRY(mbedtls_md_finish(&md_ctx, output + olen_actual));
            olen_actual += hash_len;
        } else {
            KDF2_TRY(mbedtls_md_finish(&md_ctx, hash));
            memcpy(output + olen_actual, hash, olen - olen_actual);
            olen_actual = olen;
        }
    }
exit:
    mbedtls_md_free(&md_ctx); 
    return (0 == result) ? VS_CODE_OK : VS_CODE_ERR_CRYPTO;
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

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(_hash_to_mbedtls(hash_type));

    CHECK_RET(md_info, VS_CODE_ERR_CRYPTO, "Error create kdf info");

    return _mbedtls_kdf2(md_info, input, input_sz, output, output_sz);
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

/****************************************************************/
static void
_aes_cbc_add_pkcs_padding(unsigned char *output, size_t output_len, size_t data_len) {
    size_t padding_len = output_len - data_len;
    unsigned char i;

    for (i = 0; i < padding_len; i++) {
        output[data_len + i] = (unsigned char)padding_len;
    }
}

/****************************************************************/
static int
_aes_cbc_get_pkcs_padding(unsigned char *input, size_t input_len, size_t *data_len) {
    size_t i, pad_idx;
    unsigned char padding_len, bad = 0;

    if (NULL == input || NULL == data_len)
        return (MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA);

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    /* Avoid logical || since it results in a branch */
    bad |= padding_len > input_len;
    bad |= padding_len == 0;

    /* The number of bytes checked must be independent of padding_len,
     * so pick input_len, which is usually 8 or 16 (one block) */
    pad_idx = input_len - padding_len;
    for (i = 0; i < input_len; i++)
        bad |= (input[i] ^ padding_len) * (i >= pad_idx);

    return (MBEDTLS_ERR_CIPHER_INVALID_PADDING * (bad != 0));
}

/********************************************************************************/
static vs_status_e
_aes_cbc_crypt(bool is_encrypt,
               const uint8_t *key,
               uint16_t key_bitlen,
               const uint8_t *iv,
               uint16_t iv_len,
               uint16_t buf_len,
               const uint8_t *input,
               uint8_t *output) {

    mbedtls_cipher_context_t ctx;
    vs_status_e res = VS_CODE_ERR_CRYPTO;
    size_t sz;
    uint8_t *padding_ptr;
    uint8_t tmp_padding[VS_AES_256_BLOCK_SIZE];

    CHECK_RET(VS_AES_256_KEY_BITLEN == key_bitlen, VS_CODE_ERR_NOT_IMPLEMENTED, "Unsupported key len");
    CHECK_RET(0 == mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC)),
              VS_CODE_ERR_CRYPTO,
              "Error cipher setup");
    ctx.add_padding = _aes_cbc_add_pkcs_padding;
    ctx.get_padding = _aes_cbc_get_pkcs_padding;

    CHECK(0 == mbedtls_cipher_setkey(&ctx, key, key_bitlen, is_encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) &&
                  0 == mbedtls_cipher_set_iv(&ctx, iv, iv_len) && 0 == mbedtls_cipher_reset(&ctx),
          "AES GCM CRYPTO error during initialization");

    CHECK(0 == mbedtls_cipher_update(&ctx, input, buf_len, output, &sz), "AES CBC CRYPTO error encryption/decryption");

    padding_ptr = is_encrypt ? (uint8_t *)(output + sz) : tmp_padding;

    CHECK(0 == mbedtls_cipher_finish(&ctx, padding_ptr, &sz), "AES CBC CRYPTO error encryption/decryption");

    res = VS_CODE_OK;

terminate:
    mbedtls_cipher_free(&ctx);
    return res;
}

/********************************************************************************/
static vs_status_e
_aes_gcm_crypt(bool is_encrypt,
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

    mbedtls_gcm_context ctx;
    vs_status_e res = VS_CODE_ERR_CRYPTO;
    uint8_t add_data = 0;
    uint8_t *add_ptr = &add_data;

    CHECK_NOT_ZERO_RET(tag, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(0 == add_len || add, VS_CODE_ERR_NULLPTR_ARGUMENT);

    if (NULL != add) {
        add_ptr = (uint8_t *)add;
    }
    mbedtls_gcm_init(&ctx);

    CHECK(0 == mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_bitlen) &&
                  0 == mbedtls_gcm_starts(&ctx,
                                          is_encrypt ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
                                          iv,
                                          iv_len,
                                          add_ptr,
                                          add_len),
          "AES GCM CRYPTO error during initialization");

    CHECK(0 == mbedtls_gcm_update(&ctx, buf_len, input, output), "mbedtls_gcm_update failed");

    // Auth tag check if decrypt
    if (!is_encrypt) {
        uint8_t check_tag[VS_AES_256_GCM_AUTH_TAG_SIZE];
        CHECK(0 == mbedtls_gcm_finish(&ctx, check_tag, VS_AES_256_GCM_AUTH_TAG_SIZE),
              "AES GCM CRYPTO authenticated decryption failed");
        MEMCMP_CHECK(tag, check_tag, VS_AES_256_GCM_AUTH_TAG_SIZE);
    } else {
        CHECK(0 == mbedtls_gcm_finish(&ctx, tag, tag_len), "AES GCM CRYPTO error encryption/decryption");
    }
    res = VS_CODE_OK;
terminate:

    mbedtls_gcm_free(&ctx);

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
        return _aes_gcm_crypt(true, key, key_bitlen, iv, iv_len, add, add_len, buf_len, input, output, tag, tag_len);
    case VS_AES_CBC:
        return _aes_cbc_crypt(true, key, key_bitlen, iv, iv_len, buf_len, input, output);
    default:
        VS_IOT_ASSERT(false);
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }
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
        return _aes_cbc_crypt(false, key, key_bitlen, iv, iv_len, buf_len, input, output);
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

    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(iv, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(input, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(output, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(tag, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(VS_AES_GCM == aes_type, VS_CODE_ERR_NOT_IMPLEMENTED, "AES GCM auth decrypt is only supported");

    return _aes_gcm_crypt(
            false, key, key_bitlen, iv, iv_len, add, add_len, buf_len, input, output, (uint8_t *)tag, tag_len);
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
    vs_status_e ret_code;
    vs_secmodule_keypair_type_e prvkey_type;
    int32_t slot_sz = _get_slot_size(slot);
    uint16_t private_key_sz;
    const char *pers = "virgil_compute_shared";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context private_key_ctx;
    mbedtls_pk_context public_key_ctx;
    mbedtls_ecdh_context ecdh_ctx;
    size_t required_sz;

    CHECK_NOT_ZERO_RET(public_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(public_key_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(shared_secret, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(shared_secret_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    uint8_t private_key[slot_sz];

    STATUS_CHECK_RET(vs_secmodule_keypair_get_prvkey(slot, private_key, slot_sz, &private_key_sz, &prvkey_type),
                     "Unable to load private key data from slot %s",
                     _get_slot_name(slot));
    ret_code = VS_CODE_ERR_CRYPTO;

    CHECK_RET(prvkey_type == keypair_type, VS_CODE_ERR_CRYPTO, "EC type of private and public key is not equal");

    if (keypair_type < VS_KEYPAIR_EC_SECP_MIN || keypair_type > VS_KEYPAIR_EC_SECP_MAX) {
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&private_key_ctx);
    mbedtls_pk_init(&public_key_ctx);
    VS_IOT_MEMSET(&ecdh_ctx, 0, sizeof(ecdh_ctx));

    if (_create_context_for_private_key(&private_key_ctx, private_key, private_key_sz) &&
        _create_context_for_public_key(&public_key_ctx, keypair_type, public_key, public_key_sz) &&
        0 == mbedtls_ctr_drbg_seed(
                     &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) {

        mbedtls_ecp_keypair *public_keypair = mbedtls_pk_ec(public_key_ctx);
        mbedtls_ecp_keypair *private_keypair = mbedtls_pk_ec(private_key_ctx);
        if (public_keypair && private_keypair && 0 == mbedtls_ecp_group_copy(&ecdh_ctx.grp, &public_keypair->grp) &&
            0 == mbedtls_ecp_copy(&ecdh_ctx.Qp, &public_keypair->Q) &&
            0 == mbedtls_ecp_copy(&ecdh_ctx.Q, &private_keypair->Q) &&
            0 == mbedtls_mpi_copy(&ecdh_ctx.d, &private_keypair->d) &&
            0 == mbedtls_ecdh_calc_secret(
                             &ecdh_ctx, &required_sz, shared_secret, buf_sz, mbedtls_ctr_drbg_random, &ctr_drbg)) {
                *shared_secret_sz = required_sz;
                ret_code = VS_CODE_OK;
        }
    }

    mbedtls_ecdh_free(&ecdh_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&private_key_ctx);
    mbedtls_pk_free(&public_key_ctx);

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
