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

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

#define SEQUENCE 0x30
#define OCTET_STRING 0x04
#define INTEGER 0x02
#define BIT_STRING 0x03
#define ZERO_TAG 0xA0
#define OID 0x06
#define NULL_FILED 0x05
#define SET 0x31

static const uint8_t _aes256_gcm[] =
        {0x30, 0x19, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E, 0x04, 0x0C};

static const uint8_t _aes256_cbc[] =
        {0x30, 0x1D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A, 0x04, 0x10};

static const uint8_t _pkcs7_data[] = {0x30, 0x26, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};

static const uint8_t _hmac[] = {0x30,
                                0x41,
                                0x30,
                                0x0D,
                                0x06,
                                0x09,
                                0x60,
                                0x86,
                                0x48,
                                0x01,
                                0x65,
                                0x03,
                                0x04,
                                0x02,
                                0x02,
                                0x05,
                                0x00,
                                0x04,
                                0x30};

static const uint8_t _hash_info[] = {0x30, 0x18, 0x06, 0x07, 0x28, 0x81, 0x8C, 0x71, 0x02, 0x05, 0x02, 0x30, 0x0D,
                                     0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00};

static const uint8_t _ec_type_info[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                                        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

static const uint8_t _enveloped_data_oid[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03};

static const uint8_t _sha256_oid_sequence[] =
        {0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00};

static const uint8_t _prime256v1_oid[] = {0x2a, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const uint8_t _sha384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
static const uint8_t _aes256cbc_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A};
static const uint8_t _aes256gcm_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E};

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
_asn1_put_array(uint8_t element,
                int *pos,
                uint8_t *data,
                const uint8_t *array,
                size_t array_size,
                size_t *res_size,
                size_t *total_sz) {
    int prefix_sz = 2;
    uint8_t *w;

    if (INTEGER == element && array[0] >= 0x80) {
        prefix_sz += 1;
    }
    *res_size = array_size + prefix_sz;

    if (*pos > *res_size) {
        w = &data[*pos - *res_size];
        w[0] = element;
        w[1] = array_size + prefix_sz - 2;

        if (prefix_sz > 2) {
            w[2] = 0x00;
            w += 3;
        } else {
            w += 2;
        }
        VS_IOT_MEMCPY(w, array, array_size);
        *pos -= *res_size;
        if (total_sz) {
            *total_sz += *res_size;
        }
        return true;
    }
    return false;
}

/******************************************************************************/
static bool
_asn1_put_header(uint8_t element, int *pos, uint8_t *data, size_t data_size, size_t *res_size, size_t *total_sz) {
    uint8_t *w;
    *res_size = data_size < 0x80 ? 2 : 4;

    if (*pos > *res_size) {
        w = &data[*pos - *res_size];
        w[0] = element;
        if (data_size < 0x80) {
            w[1] = data_size;
        } else {
            w[1] = 0x82;
            w[2] = data_size >> 8;
            w[3] = data_size & 0xFF;
        }
        *pos -= *res_size;
        if (total_sz) {
            *total_sz += *res_size;
        }
        return true;
    }
    return false;
}

/******************************************************************************/
static bool
_asn1_put_uint8(int *pos, uint8_t *data, uint8_t val, size_t *res_size, size_t *total_sz) {
    uint8_t *w;

    *res_size = 3;

    if (*pos > *res_size) {
        w = &data[*pos - *res_size];
        w[0] = INTEGER;
        w[1] = 1;
        w[2] = val;
        *pos -= *res_size;
        if (total_sz) {
            *total_sz += *res_size;
        }
        return true;
    }
    return false;
}

/******************************************************************************/
static bool
_asn1_put_raw(int *pos, uint8_t *data, const uint8_t *raw_data, size_t data_size, size_t *res_size, size_t *total_sz) {
    uint8_t *w;

    *res_size = data_size;

    if (*pos > *res_size) {
        w = &data[*pos - *res_size];
        VS_IOT_MEMCPY(w, raw_data, data_size);
        *pos -= *res_size;
        if (total_sz) {
            *total_sz += *res_size;
        }

        return true;
    }
    return false;
}

/******************************************************************************/
static bool
_virgil_pubkey_to_tiny_no_copy(const uint8_t *virgil_public_key, size_t virgil_key_sz, uint8_t **public_key) {
    int pos = 0;
    const uint8_t *key = 0;
    size_t key_sz = 0;

    size_t ar_sz;
    const uint8_t *p_ar = 0;

    // OID of public key
    if (!_asn1_step_into(SEQUENCE, &pos, virgil_key_sz, virgil_public_key) || //-V501
        !_asn1_step_into(SEQUENCE, &pos, virgil_key_sz, virgil_public_key) || //-V501
        !_asn1_skip(OID, &pos, virgil_key_sz, virgil_public_key) ||
        !_asn1_get_array(
                OID, &pos, _asn1_get_size(virgil_key_sz, virgil_public_key), virgil_public_key, &p_ar, &ar_sz) ||
        0 != VS_IOT_MEMCMP(p_ar, _prime256v1_oid, sizeof(_prime256v1_oid))) {
        return VS_CODE_ERR_CRYPTO;
    }

    if (_asn1_get_array(BIT_STRING, &pos, virgil_key_sz, virgil_public_key, &key, &key_sz)) {

        if (key_sz > (VS_PUBKEY_SECP256_LEN + 1) || key_sz < VS_PUBKEY_SECP256_LEN)
            return false;

        *public_key = (uint8_t *)&key[key_sz - VS_PUBKEY_SECP256_LEN];
        return true;
    }

    return false;
}

/******************************************************************************/
vs_status_e
vs_secmodule_tiny_secp256_signature_to_virgil(const uint8_t raw_signature[VS_SIGNATURE_SECP256_LEN],
                                              uint8_t *virgil_sign,
                                              uint16_t buf_sz,
                                              uint16_t *virgil_sign_sz) {
    uint8_t *buf = virgil_sign;
    int pos = buf_sz;
    size_t total_sz = 0, el_sz;
    const uint16_t secp_mpi_sz = VS_SIGNATURE_SECP256_LEN / 2;

    CHECK_NOT_ZERO_RET(raw_signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(virgil_sign, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(virgil_sign_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    if (!_asn1_put_array(INTEGER, &pos, buf, &raw_signature[secp_mpi_sz], secp_mpi_sz, &el_sz, &total_sz) ||
        !_asn1_put_array(INTEGER, &pos, buf, raw_signature, secp_mpi_sz, &el_sz, &total_sz) ||
        !_asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz) ||
        !_asn1_put_header(OCTET_STRING, &pos, buf, total_sz, &el_sz, &total_sz) ||
        !_asn1_put_raw(&pos, buf, _sha256_oid_sequence, sizeof(_sha256_oid_sequence), &el_sz, &total_sz) ||
        !_asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz) || (buf_sz < total_sz))
        return VS_CODE_ERR_CRYPTO;

    *virgil_sign_sz = total_sz;
    VS_IOT_MEMMOVE(virgil_sign, &buf[pos], total_sz);

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_secmodule_virgil_secp256_signature_to_tiny(const uint8_t *virgil_sign,
                                              uint16_t virgil_sign_sz,
                                              uint8_t *raw_signature,
                                              uint16_t buf_sz) {
    int pos = 0;

    const uint8_t *p_r = 0;
    size_t r_sz = 0;
    const uint8_t *p_s = 0;
    size_t s_sz = 0;

    const int secp_sign_sz = vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    const uint16_t secp_mpi_sz = secp_sign_sz / 2;

    CHECK_NOT_ZERO_RET(virgil_sign, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(raw_signature, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(buf_sz >= secp_sign_sz, VS_CODE_ERR_INCORRECT_PARAMETER, "Buffer too small");

    VS_IOT_MEMSET(raw_signature, 0, secp_sign_sz);
    if (_asn1_step_into(SEQUENCE, &pos, virgil_sign_sz, virgil_sign) &&
        _asn1_skip(SEQUENCE, &pos, virgil_sign_sz, virgil_sign) &&
        _asn1_step_into(OCTET_STRING, &pos, virgil_sign_sz, virgil_sign) &&
        _asn1_step_into(SEQUENCE, &pos, virgil_sign_sz, virgil_sign) &&
        _asn1_get_array(INTEGER, &pos, virgil_sign_sz, virgil_sign, &p_r, &r_sz) &&
        _asn1_get_array(INTEGER, &pos, virgil_sign_sz, virgil_sign, &p_s, &s_sz)) {

        CHECK_RET(r_sz != 0 && r_sz <= secp_mpi_sz + 2, VS_CODE_ERR_CRYPTO, "Incorrect signature r_part size %d", r_sz);
        CHECK_RET(s_sz != 0 && s_sz <= secp_mpi_sz + 2, VS_CODE_ERR_CRYPTO, "Incorrect signature s_part size %d", s_sz);

        if (0 == p_r[0]) {
            p_r += r_sz - secp_mpi_sz;
            r_sz -= (r_sz - secp_mpi_sz);
        }

        if (0 == p_s[0]) {
            p_s += s_sz - secp_mpi_sz;
            s_sz -= (s_sz - secp_mpi_sz);
        }

        VS_IOT_MEMCPY(&raw_signature[secp_mpi_sz - r_sz], p_r, r_sz);
        VS_IOT_MEMCPY(&raw_signature[secp_sign_sz - s_sz], p_s, s_sz);

        return VS_CODE_OK;
    }

    return VS_CODE_ERR_CRYPTO;
}

/******************************************************************************/
vs_status_e
vs_secmodule_virgil_cryptogram_parse_sha384_aes256(const uint8_t *cryptogram,
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

    CHECK_NOT_ZERO_RET(cryptogram, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(public_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(iv_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(encrypted_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(mac_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(iv_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(encrypted_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(encrypted_data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    _sz = cryptogram_sz;
    _data = cryptogram;

    if (_asn1_step_into(SEQUENCE, &pos, _sz, _data) && _asn1_skip(INTEGER, &pos, _sz, _data) &&
        _asn1_step_into(SEQUENCE, &pos, _sz, _data) && _asn1_skip(OID, &pos, _sz, _data) &&
        _asn1_step_into(ZERO_TAG, &pos, _sz, _data) && _asn1_step_into(SEQUENCE, &pos, _sz, _data) &&
        _asn1_skip(INTEGER, &pos, _sz, _data)) {

        set_pos = pos;
        if (!_asn1_step_into(SET, &pos, _sz, _data))
            return VS_CODE_ERR_CRYPTO;

        while (true) {
            saved_pos = pos;

            if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(INTEGER, &pos, _sz, _data) ||
                !_asn1_step_into(ZERO_TAG, &pos, _sz, _data))
                return VS_CODE_ERR_CRYPTO;

            if (recipient_id && recipient_id_sz) {
                if (!_asn1_step_into(OCTET_STRING, &pos, _sz, _data)) {
                    return VS_CODE_ERR_CRYPTO;
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
                return VS_CODE_ERR_CRYPTO;
            }

            // OID of public key
            if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(OID, &pos, _sz, _data) ||
                !_asn1_get_array(OID, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz) ||
                0 != VS_IOT_MEMCMP(p_ar, _prime256v1_oid, sizeof(_prime256v1_oid))) {
                return VS_CODE_ERR_CRYPTO;
            }

            if (!_asn1_step_into(OCTET_STRING, &pos, _sz, _data) || !_asn1_step_into(SEQUENCE, &pos, _sz, _data) ||
                !_asn1_skip(INTEGER, &pos, _sz, _data))
                return VS_CODE_ERR_CRYPTO;

            // Read public key
            if (!_virgil_pubkey_to_tiny_no_copy(&_data[pos], _asn1_get_size(pos, _data), public_key) ||
                !_asn1_skip(SEQUENCE, &pos, _sz, _data))
                return VS_CODE_ERR_CRYPTO;

            // OID of hash for kdf
            if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(OID, &pos, _sz, _data) ||
                !_asn1_step_into(SEQUENCE, &pos, _sz, _data) ||
                !_asn1_get_array(OID, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz) ||
                0 != VS_IOT_MEMCMP(p_ar, _sha384_oid, sizeof(_sha384_oid)) ||
                !_asn1_skip(NULL_FILED, &pos, _sz, _data)) {
                return VS_CODE_ERR_CRYPTO;
            }

            // Read hmac and check OID for hash
            if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_step_into(SEQUENCE, &pos, _sz, _data) || //-V501
                !_asn1_get_array(OID, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz) ||
                0 != VS_IOT_MEMCMP(p_ar, _sha384_oid, sizeof(_sha384_oid)) ||
                !_asn1_skip(NULL_FILED, &pos, _sz, _data) ||
                !_asn1_get_array(OCTET_STRING, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz)) {
                return VS_CODE_ERR_CRYPTO;
            }

            if (ar_sz != 48)
                return VS_CODE_ERR_CRYPTO;
            *mac_data = (uint8_t *)p_ar;

            // Read iv_key and check a key encryption OID
            if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_step_into(SEQUENCE, &pos, _sz, _data) || //-V501
                !_asn1_get_array(OID, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz) ||
                0 != VS_IOT_MEMCMP(p_ar, _aes256cbc_oid, sizeof(_aes256cbc_oid)) ||
                !_asn1_get_array(OCTET_STRING, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz))
                return false;

            if (ar_sz != 16)
                return VS_CODE_ERR_CRYPTO;
            *iv_key = (uint8_t *)p_ar;

            // Read encrypted_key
            if (!_asn1_get_array(OCTET_STRING, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz))
                return VS_CODE_ERR_CRYPTO;


            if (ar_sz != 48)
                return VS_CODE_ERR_CRYPTO;
            *encrypted_key = (uint8_t *)p_ar;

            pos = set_pos;
            if (!_asn1_skip(SET, &pos, _sz, _data))
                return VS_CODE_ERR_CRYPTO;
            break;
        }

        // check a data encryption OID
        if (!_asn1_step_into(SEQUENCE, &pos, _sz, _data) || !_asn1_skip(OID, &pos, _sz, _data) ||
            !_asn1_step_into(SEQUENCE, &pos, _sz, _data) ||
            !_asn1_get_array(OID, &pos, _asn1_get_size(pos, _data), _data, &p_ar, &ar_sz) ||
            0 != VS_IOT_MEMCMP(p_ar, _aes256gcm_oid, sizeof(_aes256gcm_oid)))
            return VS_CODE_ERR_CRYPTO;

        // Get IV for data (AES)
        if (!_asn1_get_array(OCTET_STRING, &pos, _sz, _data, &p_ar, &ar_sz))
            return VS_CODE_ERR_CRYPTO;

        if (ar_sz != 12)
            return VS_CODE_ERR_CRYPTO;
        *iv_data = (uint8_t *)p_ar;

        // Read encrypted data
        asn1_sz = _asn1_get_size(0, _data);
        if (_sz <= asn1_sz)
            return VS_CODE_ERR_CRYPTO;

        *encrypted_data_sz = _sz - asn1_sz;
        *encrypted_data = (uint8_t *)&_data[asn1_sz];

        return VS_CODE_OK;
    }

    return VS_CODE_ERR_CRYPTO;
}

/******************************************************************************/
vs_status_e
vs_secmodule_virgil_cryptogram_create_sha384_aes256(const uint8_t *recipient_id,
                                                    size_t recipient_id_sz,
                                                    size_t encrypted_data_sz,
                                                    const uint8_t *encrypted_data,
                                                    const uint8_t *iv_data,
                                                    const uint8_t *encrypted_key,
                                                    const uint8_t *iv_key,
                                                    const uint8_t *hmac,
                                                    const uint8_t *public_key,
                                                    size_t public_key_sz,
                                                    uint8_t *cryptogram,
                                                    size_t cryptogram_buf_sz,
                                                    size_t *cryptogram_sz) {

    uint8_t *buf = cryptogram;
    int pos = cryptogram_buf_sz;
    size_t total_sz = 0, pkcs7_data_sz = 0, el_sz;

    CHECK_NOT_ZERO_RET(recipient_id, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(recipient_id_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(encrypted_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(encrypted_data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(iv_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(encrypted_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(iv_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(hmac, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(public_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(public_key_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(cryptogram, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(cryptogram_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Put encrypted data
    if (!_asn1_put_raw(&pos, buf, encrypted_data, encrypted_data_sz, &el_sz, 0))
        return VS_CODE_ERR_CRYPTO;

    // PKCS #7 data
    if (!_asn1_put_raw(&pos, buf, iv_data, 12, &el_sz, &total_sz) ||
        !_asn1_put_raw(&pos, buf, _aes256_gcm, sizeof(_aes256_gcm), &el_sz, &total_sz) ||
        !_asn1_put_raw(&pos, buf, _pkcs7_data, sizeof(_pkcs7_data), &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    pkcs7_data_sz = total_sz;

    // AES256-GCM encrypted key
    if (!_asn1_put_array(OCTET_STRING, &pos, buf, encrypted_key, 48, &el_sz, &total_sz) ||
        !_asn1_put_raw(&pos, buf, iv_key, 16, &el_sz, &total_sz) ||
        !_asn1_put_raw(&pos, buf, _aes256_cbc, sizeof(_aes256_cbc), &el_sz, &total_sz) ||
        !_asn1_put_header(SEQUENCE, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // HMAC
    if (!_asn1_put_raw(&pos, buf, hmac, 48, &el_sz, &total_sz) ||
        !_asn1_put_raw(&pos, buf, _hmac, sizeof(_hmac), &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // hash info
    if (!_asn1_put_raw(&pos, buf, _hash_info, sizeof(_hash_info), &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // public key
    if (!_asn1_put_raw(&pos, buf, public_key, public_key_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // integer
    if (!_asn1_put_uint8(&pos, buf, 0, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // wrap with sequence
    if (!_asn1_put_header(SEQUENCE, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // wrap with octet string
    if (!_asn1_put_header(OCTET_STRING, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // EC type info
    if (!_asn1_put_raw(&pos, buf, _ec_type_info, sizeof(_ec_type_info), &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Recipient ID
    if (!_asn1_put_array(OCTET_STRING, &pos, buf, recipient_id, recipient_id_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Zero element
    if (!_asn1_put_header(ZERO_TAG, &pos, buf, el_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Integer ver
    if (!_asn1_put_uint8(&pos, buf, 2, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Wrap with sequence
    if (!_asn1_put_header(SEQUENCE, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Wrap with set
    if (!_asn1_put_header(SET, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Integer ver
    if (!_asn1_put_uint8(&pos, buf, 2, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Wrap with sequence
    if (!_asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Wrap with zero tag
    if (!_asn1_put_header(ZERO_TAG, &pos, buf, total_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // PKCS #7 enveloped data
    if (!_asn1_put_raw(&pos, buf, _enveloped_data_oid, sizeof(_enveloped_data_oid), &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Wrap with sequence
    if (!_asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Integer
    if (!_asn1_put_uint8(&pos, buf, 0, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    // Wrap with sequence
    if (!_asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz))
        return VS_CODE_ERR_CRYPTO;

    *cryptogram_sz = total_sz + encrypted_data_sz;
    VS_IOT_MEMMOVE(cryptogram, &buf[pos], *cryptogram_sz);

    return VS_CODE_OK;
}
