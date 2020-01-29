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

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <private/asn1-cryptogram.h>

#define VS_HMAC_SHA384_SIZE (VS_HASH_SHA384_LEN)

#define VS_VIRGIL_PUBKEY_MAX_SIZE (100)

static const uint8_t _secp256r1_pubkey_prefix[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
                                                   0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
                                                   0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};

/******************************************************************************/
static uint8_t
_remove_padding_size(uint8_t *data, size_t data_sz) {
    uint8_t i, padding_val;

    padding_val = data[data_sz - 1];

    if (padding_val < 2 || padding_val > 15 || data_sz < padding_val)
        return 0;

    for (i = 0; i < padding_val; ++i) {
        if (data[data_sz - 1 - i] != padding_val) {
            return 0;
        }
    }

    return padding_val;
}

/******************************************************************************/
vs_status_e
vs_secmodule_ecies_decrypt(const vs_secmodule_impl_t *secmodule_impl,
                           const uint8_t *recipient_id,
                           size_t recipient_id_sz,
                           const uint8_t *cryptogram,
                           size_t cryptogram_sz,
                           uint8_t *decrypted_data,
                           size_t buf_sz,
                           size_t *decrypted_data_sz) {

    uint8_t decrypted_key[VS_AES_256_KEY_SIZE + VS_AES_256_BLOCK_SIZE];
    uint8_t *encrypted_data;
    size_t encrypted_data_sz;
    vs_status_e ret_code;

    uint8_t pre_master_key[VS_AES_256_KEY_SIZE];
    uint16_t pre_master_key_sz;
    uint8_t master_key[VS_AES_256_KEY_SIZE + VS_HMAC_SHA384_SIZE];
    uint8_t mac_buf[VS_HMAC_SHA384_SIZE];
    uint16_t mac_sz;

    uint8_t *public_key;
    uint8_t *iv_key;
    uint8_t *encrypted_key;
    uint8_t *mac_data;
    uint8_t *iv_data;

    CHECK_NOT_ZERO_RET(secmodule_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->ecdh, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->kdf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->hmac, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->aes_decrypt, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->aes_auth_decrypt, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_NOT_ZERO_RET(cryptogram, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(cryptogram_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(decrypted_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(decrypted_data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(vs_secmodule_virgil_cryptogram_parse_sha384_aes256(cryptogram,
                                                                        cryptogram_sz,
                                                                        recipient_id,
                                                                        recipient_id_sz,
                                                                        &public_key,
                                                                        &iv_key,
                                                                        &encrypted_key,
                                                                        &mac_data,
                                                                        &iv_data,
                                                                        &encrypted_data,
                                                                        &encrypted_data_sz),
                     "Unable to parse SHA384 AES256");

    STATUS_CHECK_RET(secmodule_impl->ecdh(PRIVATE_KEY_SLOT,
                                          VS_KEYPAIR_EC_SECP256R1,
                                          public_key,
                                          vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1),
                                          pre_master_key,
                                          sizeof(pre_master_key),
                                          &pre_master_key_sz),
                     "Unable to calculate ECDH");

    STATUS_CHECK_RET(
            secmodule_impl->kdf(
                    VS_KDF_2, VS_HASH_SHA_384, pre_master_key, sizeof(pre_master_key), master_key, sizeof(master_key)),
            "Unable to calculate KDF2");

    STATUS_CHECK_RET(secmodule_impl->hmac(VS_HASH_SHA_384,
                                          master_key + VS_AES_256_KEY_SIZE,
                                          sizeof(master_key) - VS_AES_256_KEY_SIZE,
                                          encrypted_key,
                                          VS_AES_256_KEY_SIZE + VS_AES_256_BLOCK_SIZE,
                                          mac_buf,
                                          sizeof(mac_buf),
                                          &mac_sz),
                     "Unable to calculate HMAC");

    MEMCMP_CHECK_RET(mac_data, mac_buf, mac_sz, VS_CODE_ERR_CRYPTO);

    STATUS_CHECK_RET(secmodule_impl->aes_decrypt(VS_AES_CBC,
                                                 master_key,
                                                 VS_AES_256_KEY_BITLEN,
                                                 iv_key,
                                                 VS_AES_256_CBC_IV_SIZE,
                                                 NULL,
                                                 0,
                                                 sizeof(decrypted_key),
                                                 encrypted_key,
                                                 decrypted_key,
                                                 NULL,
                                                 0),
                     "Unable to descrypt");

    if (encrypted_data_sz < VS_AES_256_GCM_AUTH_TAG_SIZE ||
        buf_sz < (encrypted_data_sz - VS_AES_256_GCM_AUTH_TAG_SIZE)) {
        return VS_CODE_ERR_CRYPTO;
    }

    *decrypted_data_sz = encrypted_data_sz - VS_AES_256_GCM_AUTH_TAG_SIZE;

    STATUS_CHECK_RET(secmodule_impl->aes_auth_decrypt(VS_AES_GCM,
                                                      decrypted_key,
                                                      VS_AES_256_KEY_BITLEN,
                                                      iv_data,
                                                      VS_AES_256_GCM_IV_SIZE,
                                                      NULL,
                                                      0,
                                                      encrypted_data_sz - VS_AES_256_GCM_AUTH_TAG_SIZE,
                                                      encrypted_data,
                                                      decrypted_data,
                                                      &encrypted_data[encrypted_data_sz - VS_AES_256_GCM_AUTH_TAG_SIZE],
                                                      VS_AES_256_GCM_AUTH_TAG_SIZE),
                     "Unable to decrypt");

    *decrypted_data_sz -= _remove_padding_size(decrypted_data, *decrypted_data_sz);

    return VS_CODE_OK;
}

/******************************************************************************/
static bool
_tiny_pubkey_to_virgil(uint8_t public_key[64], uint8_t *virgil_public_key, size_t *virgil_public_key_sz) {
    if (*virgil_public_key_sz < (sizeof(_secp256r1_pubkey_prefix) + 64))
        return false;

    VS_IOT_MEMCPY(virgil_public_key, _secp256r1_pubkey_prefix, sizeof(_secp256r1_pubkey_prefix));
    VS_IOT_MEMCPY(&virgil_public_key[sizeof(_secp256r1_pubkey_prefix)], public_key, 64);
    *virgil_public_key_sz = sizeof(_secp256r1_pubkey_prefix) + 64;
    return true;
}

/******************************************************************************/
vs_status_e
vs_secmodule_ecies_encrypt(const vs_secmodule_impl_t *secmodule_impl,
                           const uint8_t *recipient_id,
                           size_t recipient_id_sz,
                           const uint8_t *data,
                           size_t data_sz,
                           uint8_t *cryptogram,
                           size_t buf_sz,
                           size_t *cryptogram_sz) {
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(secmodule_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->get_pubkey, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->random, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->ecdh, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->kdf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->aes_encrypt, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule_impl->hmac, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(cryptogram, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(cryptogram_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    vs_secmodule_keypair_type_e ec_type;
    uint16_t key_sz = vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    uint8_t pubkey[key_sz];

    uint8_t pre_master_key[VS_AES_256_KEY_SIZE];
    uint16_t pre_master_key_sz;
    uint8_t master_key[VS_AES_256_KEY_SIZE + VS_HMAC_SHA384_SIZE];

    uint8_t encrypted_key[VS_AES_256_KEY_SIZE + VS_AES_256_BLOCK_SIZE];

    uint8_t hmac[VS_HMAC_SHA384_SIZE];
    uint16_t hmac_sz;

    uint8_t virgil_public_key[VS_VIRGIL_PUBKEY_MAX_SIZE];
    size_t virgil_public_key_sz = sizeof(virgil_public_key);

    uint8_t rnd_buf[VS_AES_256_CBC_IV_SIZE + VS_AES_256_GCM_IV_SIZE + VS_AES_256_KEY_SIZE];
    uint8_t *iv_key = rnd_buf;
    uint8_t *iv_data = &rnd_buf[VS_AES_256_GCM_IV_SIZE];
    uint8_t *shared_key = &rnd_buf[VS_AES_256_CBC_IV_SIZE + VS_AES_256_GCM_IV_SIZE];

    CHECK_NOT_ZERO_RET(secmodule_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);

    if (VS_CODE_OK != secmodule_impl->get_pubkey(PRIVATE_KEY_SLOT, pubkey, key_sz, &key_sz, &ec_type) ||
        !_tiny_pubkey_to_virgil(&pubkey[1], virgil_public_key, &virgil_public_key_sz)) {
        return VS_CODE_ERR_CRYPTO;
    }

    STATUS_CHECK_RET(secmodule_impl->random(rnd_buf, sizeof(rnd_buf)), "Unable to generate random buffer");

    STATUS_CHECK_RET(secmodule_impl->ecdh(PRIVATE_KEY_SLOT,
                                          VS_KEYPAIR_EC_SECP256R1,
                                          pubkey,
                                          vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1),
                                          pre_master_key,
                                          sizeof(pre_master_key),
                                          &pre_master_key_sz),
                     "Unable to calculate ECDH");

    STATUS_CHECK_RET(
            secmodule_impl->kdf(
                    VS_KDF_2, VS_HASH_SHA_384, pre_master_key, sizeof(pre_master_key), master_key, sizeof(master_key)),
            "Unable to calculate KDF");

    STATUS_CHECK_RET(secmodule_impl->aes_encrypt(VS_AES_CBC,
                                                 master_key,
                                                 VS_AES_256_KEY_BITLEN,
                                                 iv_key,
                                                 VS_AES_256_CBC_IV_SIZE,
                                                 NULL,
                                                 0,
                                                 VS_AES_256_KEY_SIZE,
                                                 shared_key,
                                                 encrypted_key,
                                                 NULL,
                                                 0),
                     "Unable to encrypt by using AES");

    STATUS_CHECK_RET(secmodule_impl->hmac(VS_HASH_SHA_384,
                                          master_key + VS_AES_256_KEY_SIZE,
                                          sizeof(master_key) - VS_AES_256_KEY_SIZE,
                                          encrypted_key,
                                          sizeof(encrypted_key),
                                          hmac,
                                          sizeof(hmac),
                                          &hmac_sz),
                     "Unable to calculate HMAC");

    uint8_t add_data = 0;
    uint8_t encrypted_data[data_sz + VS_AES_256_GCM_AUTH_TAG_SIZE];

    STATUS_CHECK_RET(secmodule_impl->aes_encrypt(VS_AES_GCM,
                                                 shared_key,
                                                 VS_AES_256_KEY_BITLEN,
                                                 iv_data,
                                                 VS_AES_256_GCM_IV_SIZE,
                                                 &add_data,
                                                 0,
                                                 data_sz,
                                                 data,
                                                 encrypted_data,
                                                 &encrypted_data[sizeof(encrypted_data) - VS_AES_256_GCM_AUTH_TAG_SIZE],
                                                 VS_AES_256_GCM_AUTH_TAG_SIZE),
                     "Unable to encrypt by using AES");

    return vs_secmodule_virgil_cryptogram_create_sha384_aes256(recipient_id,
                                                               recipient_id_sz,
                                                               sizeof(encrypted_data),
                                                               encrypted_data,
                                                               iv_data,
                                                               encrypted_key,
                                                               iv_key,
                                                               hmac,
                                                               virgil_public_key,
                                                               virgil_public_key_sz,
                                                               cryptogram,
                                                               buf_sz,
                                                               cryptogram_sz);
}

/******************************************************************************/
