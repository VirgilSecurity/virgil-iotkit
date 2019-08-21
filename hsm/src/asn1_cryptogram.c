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

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/hsm/hsm_errors.h>

#define SEQUENCE 0x30
#define OCTET_STRING 0x04
#define INTEGER 0x02
#define BIT_STRING 0x03
#define ZERO_TAG 0xA0
#define OID 0x06
#define SET 0x31

/******************************************************************************/
static bool
_asn1_step_into(uint8_t element, int *pos, const int sz, const uint8_t *data) {
    if (element != data[*pos] || (2 + *pos) >= sz)
        return false;

    if (data[1 + *pos] >= 0x80) {
        *pos += data[1 + *pos] & 0x0F;
    }
    *pos += 2;

    return true;
}

/******************************************************************************/
static bool
_asn1_skip(uint8_t element, int *pos, const int sz, const uint8_t *data) {
    size_t element_sz, sz_bytes;
    if (element != data[*pos])
        return false;

    if (0x80 > data[1 + *pos]) {
        element_sz = data[1 + *pos];
        *pos += 2 + element_sz;
    } else {
        sz_bytes = data[1 + *pos] & 0x0F;
        element_sz = data[2 + *pos];
        if (2 == sz_bytes) {
            element_sz <<= 8;
            element_sz += data[3 + *pos];
        }
        *pos += 2 + sz_bytes + element_sz;
    }
    return true;
}

/******************************************************************************/
static bool
_asn1_get_array(uint8_t element,
                int *pos,
                const int sz,
                const uint8_t *data,
                const uint8_t **array,
                size_t *array_size) {
    size_t element_sz;
    if (element == data[*pos]) {
        element_sz = data[1 + *pos];
        if (0x80 > element_sz) {
            *array_size = element_sz;
            *array = &data[2 + *pos];
            *pos += 2 + element_sz;
            return true;
        }
    }
    return false;
}


/******************************************************************************/
static size_t
_asn1_get_size(int pos, const uint8_t *data) {
    size_t i, cnt = 0, res = 0;

    if (data[1 + pos] > 0x80) {
        cnt = data[1 + pos] & 0x7F;
        if (cnt > 2)
            return res;

        for (i = 0; i < cnt; ++i) {
            res <<= 8;
            res |= data[2 + i + pos];
        }

        res += 2 + cnt;
    } else {
        res = data[1 + pos] + 2;
    }

    return res;
}

/******************************************************************************/
static bool
_virgil_pubkey_to_tiny_no_copy(const uint8_t *virgil_public_key, size_t virgil_public_key_sz, uint8_t **public_key) {
    int pos = 0;
    const uint8_t *key = 0;
    size_t key_sz = 0;

    if (_asn1_step_into(SEQUENCE, &pos, virgil_public_key_sz, virgil_public_key) &&
        _asn1_skip(SEQUENCE, &pos, virgil_public_key_sz, virgil_public_key) &&
        _asn1_get_array(BIT_STRING, &pos, virgil_public_key_sz, virgil_public_key, &key, &key_sz)) {

        if (key_sz > 66 || key_sz < 64)
            return false;

        *public_key = (uint8_t *)&key[key_sz - 65];
        return true;
    }

    return false;
}

/******************************************************************************/
int
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
                                             size_t *encrypted_data_sz) {

    int pos = 0, saved_pos, set_pos = 0;
    size_t _sz, ar_sz, asn1_sz;
    const uint8_t *_data, *p_ar = 0;

    CHECK_NOT_ZERO(cryptogram, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO(public_key, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO(iv_key, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO(encrypted_key, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO(mac_data, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO(iv_data, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO(encrypted_data, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO(encrypted_data_sz, VS_HSM_ERR_INVAL);

    _sz = cryptogram_sz;
    _data = cryptogram;

    if (_asn1_step_into(SEQUENCE, &pos, _sz, _data) && _asn1_skip(INTEGER, &pos, _sz, _data) &&
        _asn1_step_into(SEQUENCE, &pos, _sz, _data) && _asn1_skip(OID, &pos, _sz, _data) &&
        _asn1_step_into(ZERO_TAG, &pos, _sz, _data) && _asn1_step_into(SEQUENCE, &pos, _sz, _data) &&
        _asn1_skip(INTEGER, &pos, _sz, _data)) {

        set_pos = pos;
        if (!_asn1_step_into(SET, &pos, _sz, _data))
            return VS_HSM_ERR_CRYPTO;

        while (true) {
            saved_pos = pos;

            if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(INTEGER, &pos, _sz, _data) ||
                !_asn1_step_into(ZERO_TAG, &pos, _sz, _data))
                return VS_HSM_ERR_CRYPTO;

            if (recipient_id && recipient_id_sz) {
                if (!_asn1_step_into(OCTET_STRING, &pos, _sz, _data)) {
                    return VS_HSM_ERR_CRYPTO;
                }
                // Find out need recipient
                if (0 != VS_IOT_MEMCMP(&_data[pos], recipient_id, recipient_id_sz)) {
                    pos = saved_pos;
                    if (!_asn1_skip(SEQUENCE, &pos, _sz, _data))
                        return false;
                    continue;
                }

                pos += recipient_id_sz;
            } else if (!_asn1_skip(OCTET_STRING, &pos, _sz, _data)) {
                return VS_HSM_ERR_CRYPTO;
            }

            if (!_asn1_skip(SEQUENCE, &pos, _sz, _data) || !_asn1_step_into(OCTET_STRING, &pos, _sz, _data) ||
                !_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(INTEGER, &pos, _sz, _data))
                return VS_HSM_ERR_CRYPTO;

            // Read public key
            if (!_virgil_pubkey_to_tiny_no_copy(&_data[pos], _asn1_get_size(pos, _data), public_key))
                return VS_HSM_ERR_CRYPTO;

            if (!_asn1_skip(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(SEQUENCE, &pos, _sz, _data)) //-V501
                return VS_HSM_ERR_CRYPTO;

            saved_pos = pos;
            // Read mac
            if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(SEQUENCE, &pos, _sz, _data) ||
                !_asn1_get_array(OCTET_STRING, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz))
                return VS_HSM_ERR_CRYPTO;

            if (ar_sz != 48)
                return VS_HSM_ERR_CRYPTO;
            *mac_data = (uint8_t *)p_ar;

            pos = saved_pos;

            if (!_asn1_skip(SEQUENCE, &pos, _sz, _data) || !_asn1_step_into(SEQUENCE, &pos, _sz, _data))
                return VS_HSM_ERR_CRYPTO;

            saved_pos = pos;

            // Read iv_key
            if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(OID, &pos, _sz, _data) ||
                !_asn1_get_array(OCTET_STRING, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz))
                return false;

            if (ar_sz != 16)
                return VS_HSM_ERR_CRYPTO;
            *iv_key = (uint8_t *)p_ar;

            pos = saved_pos;

            // Read encrypted_key
            if (!_asn1_skip(SEQUENCE, &pos, _sz, _data) ||
                !_asn1_get_array(OCTET_STRING, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz))
                return VS_HSM_ERR_CRYPTO;


            if (ar_sz != 48)
                return VS_HSM_ERR_CRYPTO;
            *encrypted_key = (uint8_t *)p_ar;

            pos = set_pos;
            if (!_asn1_skip(SET, &pos, _sz, _data))
                return VS_HSM_ERR_CRYPTO;
            break;
        }

        if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(OID, &pos, _sz, _data) ||
            !_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(OID, &pos, _sz, _data))
            return VS_HSM_ERR_CRYPTO;

        // Get IV for data (AES)
        if (!_asn1_get_array(OCTET_STRING, &pos, _sz, _data, &p_ar, &ar_sz))
            return VS_HSM_ERR_CRYPTO;

        if (ar_sz != 12)
            return VS_HSM_ERR_CRYPTO;
        *iv_data = (uint8_t *)p_ar;

        // Read encrypted data
        asn1_sz = _asn1_get_size(0, _data);
        if (_sz <= asn1_sz)
            return VS_HSM_ERR_FAIL;

        *encrypted_data_sz = _sz - asn1_sz;
        *encrypted_data = (uint8_t *)&_data[asn1_sz];

        return VS_HSM_ERR_OK;
    }

    return VS_HSM_ERR_FAIL;
}
