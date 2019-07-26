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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <virgil/iot/macros/macros.h>

#include <virgil/iot/cloud/cloud.h>
#include <virgil/iot/cloud/private/cloud_hal.h>
#include <virgil/iot/cloud/private/cloud_operations.h>
#include <virgil/iot/cloud/private/asn1_cryptogram.h>
#include <virgil/iot/cloud/base64/base64.h>
#include <virgil/iot/json/json_parser.h>
#include <virgil/iot/update/update.h>
#include <stdlib-config.h>
#include <cloud-config.h>
#include <global-hal.h>

#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/logger/logger.h>

#define MAX_EP_SIZE (256)

/******************************************************************************/
static bool
_data_to_hex(const uint8_t *_data, uint32_t _len, uint8_t *_out_data, uint32_t *_in_out_len) {
    const uint8_t hex_str[] = "0123456789abcdef";

    if (!_len) {
        return false;
    }

    if (*_in_out_len < _len * 2 + 1) {
        return false;
    }

    *_in_out_len = _len * 2 + 1;
    _out_data[*_in_out_len - 1] = 0;
    size_t i;

    for (i = 0; i < _len; i++) {
        _out_data[i * 2 + 0] = hex_str[(_data[i] >> 4) & 0x0F];
        _out_data[i * 2 + 1] = hex_str[(_data[i]) & 0x0F];
    }
    return true;
}

/******************************************************************************/
static void
_get_serial_number_in_hex_str(char _out_str[SERIAL_SIZE * 2 + 1]) {
    uint8_t serial_number[SERIAL_SIZE];
    uint32_t _in_out_len = SERIAL_SIZE * 2 + 1;
    vs_global_hal_get_udid_of_device(serial_number);
    _data_to_hex(serial_number, SERIAL_SIZE, (uint8_t *)_out_str, &_in_out_len);
}

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
static bool
_crypto_decrypt_sha384_aes256(uint8_t *cryptogram,
                              size_t cryptogram_sz,
                              uint8_t *decrypted_data,
                              size_t buf_sz,
                              size_t *decrypted_data_sz) {
    uint8_t decrypted_key[48];
    uint8_t *encrypted_data;
    size_t encrypted_data_sz;

    uint8_t pre_master_key[32];
    uint16_t pre_master_key_sz;
    uint8_t master_key[80];
    uint8_t mac_buf[48];
    uint16_t mac_sz;

    uint8_t *public_key;
    uint8_t *iv_key;
    uint8_t *encrypted_key;
    uint8_t *mac_data;
    uint8_t *iv_data;

    if (VS_CLOUD_ERR_OK != vs_cloud_virgil_cryptogram_parse_sha384_aes256(cryptogram,
                                                                          cryptogram_sz,
                                                                          &public_key,
                                                                          &iv_key,
                                                                          &encrypted_key,
                                                                          &mac_data,
                                                                          &iv_data,
                                                                          &encrypted_data,
                                                                          &encrypted_data_sz)) {
        return false;
    }

    if (VS_HSM_ERR_OK != vs_hsm_ecdh(PRIVATE_KEY_SLOT,
                                     VS_KEYPAIR_EC_SECP256R1,
                                     public_key,
                                     vs_hsm_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1),
                                     pre_master_key,
                                     sizeof(pre_master_key),
                                     &pre_master_key_sz) ||
        VS_HSM_ERR_OK != vs_hsm_kdf(VS_KDF_2,
                                    VS_HASH_SHA_384,
                                    pre_master_key,
                                    sizeof(pre_master_key),
                                    master_key,
                                    sizeof(master_key)) ||
        VS_HSM_ERR_OK != vs_hsm_hmac(VS_HASH_SHA_384,
                                     master_key + 32,
                                     sizeof(master_key) - 32,
                                     encrypted_key,
                                     48,
                                     mac_buf,
                                     sizeof(mac_buf),
                                     &mac_sz) ||
        0 != memcmp(mac_data, mac_buf, mac_sz) ||
        VS_HSM_ERR_OK != vs_hsm_aes_decrypt(VS_AES_CBC,
                                            master_key,
                                            32 * 8,
                                            iv_key,
                                            16,
                                            NULL,
                                            0,
                                            48,
                                            encrypted_key,
                                            decrypted_key,
                                            NULL,
                                            0)) {
        return false;
    }

    if (buf_sz < encrypted_data_sz) {
        return false;
    }

    *decrypted_data_sz = encrypted_data_sz - 16;

    if (VS_HSM_ERR_OK != vs_hsm_aes_auth_decrypt(VS_AES_GCM,
                                                 decrypted_key,
                                                 32 * 8,
                                                 iv_data,
                                                 12,
                                                 NULL,
                                                 0,
                                                 encrypted_data_sz - 16,
                                                 encrypted_data,
                                                 decrypted_data,
                                                 &encrypted_data[encrypted_data_sz - 16],
                                                 16)) {
        return false;
    }

    *decrypted_data_sz -= _remove_padding_size(decrypted_data, *decrypted_data_sz);

    return true;
}

/******************************************************************************/
static int16_t
_decrypt_answer(char *out_answer, size_t *in_out_answer_len) {
    jobj_t jobj;
    size_t buf_size = *in_out_answer_len;

    if (json_parse_start(&jobj, out_answer, buf_size) != VS_JSON_ERR_OK) {
        return VS_CLOUD_ERR_FAIL;
    }

    char *crypto_answer_b64 = (char *)VS_IOT_MALLOC(buf_size);

    int crypto_answer_b64_len;

    if (json_get_val_str(&jobj, "encrypted_value", crypto_answer_b64, (int)buf_size) != VS_JSON_ERR_OK)
        return VS_CLOUD_ERR_FAIL;
    else {
        crypto_answer_b64_len = base64decode_len(crypto_answer_b64, (int)strlen(crypto_answer_b64));

        if (0 >= crypto_answer_b64_len || crypto_answer_b64_len > buf_size) {
            goto fail;
        }

        base64decode(crypto_answer_b64,
                     (int)strlen(crypto_answer_b64),
                     (uint8_t *)crypto_answer_b64,
                     &crypto_answer_b64_len);
        size_t decrypted_data_sz;

        if (!_crypto_decrypt_sha384_aes256((uint8_t *)crypto_answer_b64,
                                           (size_t)crypto_answer_b64_len,
                                           (uint8_t *)out_answer,
                                           buf_size,
                                           &decrypted_data_sz) ||
            decrypted_data_sz > UINT16_MAX) {
            goto fail;
        }
        *in_out_answer_len = (uint16_t)decrypted_data_sz;
        out_answer[*in_out_answer_len] = '\0';
    }
    VS_IOT_FREE(crypto_answer_b64);
    return VS_CLOUD_ERR_OK;

fail:
    VS_IOT_FREE(crypto_answer_b64);
    *in_out_answer_len = 0;
    out_answer[0] = '\0';
    return VS_CLOUD_ERR_FAIL;
}

/******************************************************************************/
static int
_get_credentials(char *host, char *ep, char *id, char *out_answer, size_t *in_out_answer_len) {
    int16_t ret;
    char serial[SERIAL_SIZE * 2 + 1];

    CHECK_NOT_ZERO(out_answer, VS_CLOUD_ERR_INVAL);
    CHECK_NOT_ZERO(in_out_answer_len, VS_CLOUD_ERR_INVAL);

    char *url = (char *)VS_IOT_MALLOC(MAX_EP_SIZE);

    _get_serial_number_in_hex_str(serial);

    int res = VS_IOT_SNPRINTF(url, MAX_EP_SIZE, "%s/%s/%s/%s", host, ep, serial, id);
    if (res < 0 || res > MAX_EP_SIZE ||
        https(VS_HTTP_GET, url, NULL, NULL, 0, out_answer, in_out_answer_len) != HTTPS_RET_CODE_OK) {
        ret = VS_CLOUD_ERR_FAIL;
    } else {
        ret = _decrypt_answer(out_answer, in_out_answer_len);
    }

    VS_IOT_FREE(url);
    return ret;
}

/******************************************************************************/
int
vs_cloud_fetch_amazon_credentials(char *out_answer, size_t *in_out_answer_len) {
    return _get_credentials(VS_CLOUD_HOST, VS_THING_EP, VS_AWS_ID, out_answer, in_out_answer_len);
}

/******************************************************************************/
int
vs_cloud_fetch_message_bin_credentials(char *out_answer, size_t *in_out_answer_len) {
    return _get_credentials(VS_CLOUD_HOST, VS_THING_EP, VS_MQTT_ID, out_answer, in_out_answer_len);
}

/*************************************************************************/
int
vs_cloud_fetch_firmware(void *data_source, vs_firmware_info_t *fw_info) {
    return VS_CLOUD_ERR_OK;
}

/*************************************************************************/
int
vs_cloud_fetch_and_store_fw_file(const char *fw_file_url, void *pData) {
    return VS_CLOUD_ERR_OK;
}

/*************************************************************************/
int
vs_cloud_fetch_tl(void *data_source, vs_tl_info_t *tl_info) {
    return VS_CLOUD_ERR_OK;
}

/*************************************************************************/
int
vs_cloud_fetch_and_store_tl(const char *tl_file_url, void *pData) {
    return VS_CLOUD_ERR_OK;
}