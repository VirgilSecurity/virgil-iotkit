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

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>

#include <virgil/iot/vs-ateccx08A-secmodule/vs-ateccx08A-secmodule.h>
#include <private/vs-ateccx08A-secmodule-internal.h>

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

    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
static vs_status_e
vs_secmodule_ecdsa_sign(vs_iot_secmodule_slot_e key_slot,
                        vs_secmodule_hash_type_e hash_type,
                        const uint8_t *hash,
                        uint8_t *signature,
                        uint16_t signature_buf_sz,
                        uint16_t *signature_sz) {

    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return VS_CODE_ERR_NOT_IMPLEMENTED;
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

    CHECK_NOT_ZERO_RET(public_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(public_key_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hash, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(signature_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return VS_CODE_ERR_NOT_IMPLEMENTED;
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


    return VS_CODE_ERR_NOT_IMPLEMENTED;
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

    return VS_CODE_ERR_NOT_IMPLEMENTED;
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

    return VS_CODE_ERR_NOT_IMPLEMENTED;
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

    CHECK_NOT_ZERO_RET(public_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(shared_secret, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(shared_secret_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

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
