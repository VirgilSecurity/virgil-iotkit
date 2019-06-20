/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file asn1-converters.c
 * @brief Conversion between virgil asn1 structures and plain data for atecc508a
 */

#include <string.h>
#include <stdbool.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/base64.h>

#include <stdio.h>

#include "virgil/iot/converters/asn1.h"
#include "virgil/iot/converters/converters_mbedtls.h"

#define ASN1_CHK_ADD(g, f)                                                                                             \
    do {                                                                                                               \
        if ((res_sz = f) < 0)                                                                                          \
            return (false);                                                                                            \
        else                                                                                                           \
            g += res_sz;                                                                                               \
    } while (0)

static const uint8_t _sha256_oid_sequence[] =
        {0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00};

static const uint8_t _pubkey_prefix[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
                                         0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
                                         0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};

/******************************************************************************/
bool
tiny_nist256_sign_to_virgil(uint8_t sign[64], uint8_t *virgil_sign, size_t *virgil_sign_sz) {
    uint8_t buf[256];
    int pos = sizeof(buf);
    size_t total_sz = 0, el_sz;

    if (!asn1_put_array(INTEGER, &pos, buf, &sign[32], 32, &el_sz, &total_sz) ||
        !asn1_put_array(INTEGER, &pos, buf, sign, 32, &el_sz, &total_sz) ||
        !asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz) ||
        !asn1_put_header(OCTET_STRING, &pos, buf, total_sz, &el_sz, &total_sz) ||
        !asn1_put_raw(&pos, buf, _sha256_oid_sequence, sizeof(_sha256_oid_sequence), &el_sz, &total_sz) ||
        !asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz) || (*virgil_sign_sz < total_sz))
        return false;

    *virgil_sign_sz = total_sz;
    memcpy(virgil_sign, &buf[pos], total_sz);

    return true;
}

/******************************************************************************/
bool
tiny_nist256_pubkey_to_virgil(uint8_t public_key[64], uint8_t *virgil_public_key, size_t *virgil_public_key_sz) {
    if (*virgil_public_key_sz < (sizeof(_pubkey_prefix) + 64))
        return false;

    memcpy(virgil_public_key, _pubkey_prefix, sizeof(_pubkey_prefix));
    memcpy(&virgil_public_key[sizeof(_pubkey_prefix)], public_key, 64);
    *virgil_public_key_sz = sizeof(_pubkey_prefix) + 64;
    return true;
}

/******************************************************************************/
bool
virgil_sign_to_mbedtls(const uint8_t *virgil_sign, size_t virgil_sign_sz, const uint8_t **sign, size_t *sign_sz) {
    uint8_t *p = (uint8_t *)virgil_sign;
    uint8_t *end = p + virgil_sign_sz;
    size_t len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) || p + len != end ||
        0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return false;
    }

    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) {
        return false;
    }

    *sign_sz = len;
    *sign = p;

    return true;
}

/******************************************************************************/
bool
mbedtls_sign_to_virgil(uint8_t hash_type,
                       uint8_t *mbedtls_sign,
                       size_t mbedtls_sign_sz,
                       uint8_t *virgil_sign,
                       size_t buf_sz,
                       uint16_t *virgil_sign_sz) {
    int res_sz;
    unsigned char *buf = virgil_sign;
    unsigned char *p = buf + buf_sz;
    uint16_t len = 0;
    size_t hash_type_len = 0;
    const char *oid = 0;
    size_t oid_len;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&p, buf, mbedtls_sign, mbedtls_sign_sz));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_OCTET_STRING));

    ASN1_CHK_ADD(hash_type_len, mbedtls_asn1_write_null(&p, buf));

    if (0 != mbedtls_oid_get_oid_by_md(hash_type, &oid, &oid_len))
        return false;

    ASN1_CHK_ADD(hash_type_len, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, hash_type_len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len + hash_type_len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += hash_type_len;

    if (buf_sz > len) {
        memmove(virgil_sign, p, len);
    }

    *virgil_sign_sz = len;

    return true;
}

/******************************************************************************/
bool
virgil_cryptogram_create_mbedtls(const uint8_t *recipient_id,
                                 size_t recipient_id_sz,
                                 const uint8_t *encrypted_key,
                                 size_t encrypted_key_sz,
                                 const uint8_t *encrypted_data,
                                 size_t encrypted_data_sz,
                                 const uint8_t iv_data[16],
                                 uint8_t *cryptogram,
                                 size_t buf_sz,
                                 size_t *cryptogram_sz) {
    int res_sz;
    unsigned char *buf = cryptogram;
    unsigned char *p;
    size_t len = 0, len_top = 0, len_tmp = 0;

    uint8_t pkcs7_data_oid[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};
    uint8_t pkcs7_envelop_data_oid[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03};

    const char *oid = 0;
    size_t oid_len;

    if (buf_sz <= (encrypted_data_sz + encrypted_key_sz))
        return false;

    memcpy(&cryptogram[buf_sz - encrypted_data_sz], encrypted_data, encrypted_data_sz);

    p = cryptogram + buf_sz - encrypted_data_sz;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(&p, buf, iv_data, 16));

    if (0 != mbedtls_oid_get_oid_by_cipher_alg(MBEDTLS_CIPHER_AES_128_CBC, &oid, &oid_len))
        return false;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(&p, buf, (char *)pkcs7_data_oid, sizeof(pkcs7_data_oid)));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len_top, mbedtls_asn1_write_octet_string(&p, buf, encrypted_key, encrypted_key_sz));


    if (0 != mbedtls_oid_get_oid_by_ec_grp(MBEDTLS_ECP_DP_SECP256R1, &oid, &oid_len))
        return false;
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));
    if (0 != mbedtls_oid_get_oid_by_pk_alg(MBEDTLS_PK_ECKEY, &oid, &oid_len))
        return false;
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_len(&p, buf, len_tmp));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len_top += len_tmp;
    len_tmp = 0;

    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_octet_string(&p, buf, (unsigned char *)recipient_id, recipient_id_sz));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_len(&p, buf, len_tmp));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC));

    len_top += len_tmp;
    len_tmp = 0;

    ASN1_CHK_ADD(len_top, mbedtls_asn1_write_int(&p, buf, 2));

    ASN1_CHK_ADD(len_top, mbedtls_asn1_write_len(&p, buf, len_top));
    ASN1_CHK_ADD(len_top, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len_top, mbedtls_asn1_write_len(&p, buf, len_top));
    ASN1_CHK_ADD(len_top, mbedtls_asn1_write_tag(&p, buf, 0x31));

    len += len_top;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, buf, 2));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));


    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(&p, buf, (char *)pkcs7_envelop_data_oid, sizeof(pkcs7_envelop_data_oid)));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, buf, 0));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += encrypted_data_sz;
    *cryptogram_sz = len;

    if (len != buf_sz) {
        memmove(cryptogram, p, len);
    }

    return true;
}

/******************************************************************************/
bool
virgil_cryptogram_parse_mbedtls(const uint8_t *virgil_encrypted_data,
                                size_t virgil_encrypted_data_sz,
                                const uint8_t *recipient_id,
                                size_t recipient_id_sz,
                                uint8_t **iv,
                                uint8_t **encrypted_key,
                                size_t *encrypted_key_sz,
                                uint8_t **encrypted_data,
                                size_t *encrypted_data_sz) {

    uint8_t *p;
    uint8_t *end;
    uint8_t *saved_p, *top_p;
    size_t len, saved_len, top_len;
    int int_tmp;


    if (!virgil_encrypted_data || virgil_encrypted_data_sz < 300 || !recipient_id) {
        return false;
    }

    p = (uint8_t *)virgil_encrypted_data;
    end = p + virgil_encrypted_data_sz;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return false;
    }

    *encrypted_data_sz = virgil_encrypted_data_sz - len;
    *encrypted_data_sz -= p - virgil_encrypted_data;
    *encrypted_data = (uint8_t *)&virgil_encrypted_data[virgil_encrypted_data_sz - *encrypted_data_sz];

    if (0 != mbedtls_asn1_get_int(&p, end, &int_tmp))
        return false;
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return false;
    }
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID))
        return false;
    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC)) {
        return false;
    }

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return false;
    }

    if (0 != mbedtls_asn1_get_int(&p, end, &int_tmp))
        return false;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET))
        return false;

    top_p = p;
    top_len = len;

    // Header has been skipped. Let's iterate throw recipients

    while (true) {
        if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
            return false;
        }

        saved_p = p;
        saved_len = len;

        if (0 != mbedtls_asn1_get_int(&p, end, &int_tmp))
            return false;
        if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC)) {
            return false;
        }

        if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING))
            return false;

        if (0 != memcmp(p, recipient_id, len)) {
            // skip sequence if not need recipient id
            p = saved_p + saved_len;
            continue;
        }

        p += len;

        if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
            return false;
        }

        p += len;

        if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING))
            return false;

        *encrypted_key_sz = len;
        *encrypted_key = p;

        p = top_p + top_len;

        break;
    }

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return false;
    }
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID))
        return false;
    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return false;
    }
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID))
        return false;
    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING))
        return false;

    if (16 != len)
        return false;

    *iv = p;

    return true;
}

/******************************************************************************/
bool
mbedtls_cryptogram_parse_low_level(const uint8_t *cryptogram,
                                   size_t cryptogram_sz,
                                   uint8_t **public_key,
                                   uint8_t **iv,
                                   uint8_t **hmac,
                                   uint8_t **encrypted_data,
                                   size_t *encrypted_data_sz) {

    uint8_t *p;
    uint8_t *end;
    size_t len;
    int int_tmp;
    mbedtls_asn1_bitstring bs;

    if (!cryptogram || cryptogram_sz < 64) {
        return false;
    }

    p = (uint8_t *)cryptogram;
    end = p + cryptogram_sz;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    if (0 != mbedtls_asn1_get_int(&p, end, &int_tmp))
        return false;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    p += len;
    memset(&bs, 0, sizeof(mbedtls_asn1_bitstring));
    mbedtls_asn1_get_bitstring(&p, end, &bs);

    if (bs.len > 66 || bs.len < 64)
        return false;
    *public_key = (uint8_t *)&bs.p[bs.len - 64];

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING))
        return false;
    *hmac = p;
    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID))
        return false;
    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING))
        return false;
    *iv = p;
    p += len;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING))
        return false;
    *encrypted_data = p;
    *encrypted_data_sz = len;

    return true;
}

/******************************************************************************/
bool
low_level_cryptogram_create_mbedtls(const uint8_t *public_key,
                                    size_t public_key_sz,
                                    const uint8_t *encrypted_data,
                                    size_t encrypted_data_sz,
                                    const uint8_t hmac[32],
                                    const uint8_t iv_data[16],
                                    uint8_t *cryptogram,
                                    size_t buf_sz,
                                    size_t *cryptogram_sz) {

    int res_sz;
    unsigned char *buf = cryptogram;
    unsigned char *p = buf + buf_sz;
    size_t len = 0, len_sec = 0, len_tmp = 0;

    uint8_t additional_oid[7] = {0x28, 0x81, 0x8C, 0x71, 0x02, 0x05, 0x02};

    const char *oid = 0;
    size_t oid_len;

    ASN1_CHK_ADD(len_sec, mbedtls_asn1_write_octet_string(&p, buf, encrypted_data, encrypted_data_sz));


    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_octet_string(&p, buf, iv_data, 16));

    if (0 != mbedtls_oid_get_oid_by_cipher_alg(MBEDTLS_CIPHER_AES_128_CBC, &oid, &oid_len))
        return false;

    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));

    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_len(&p, buf, len_tmp));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len_sec + len_tmp));
    ASN1_CHK_ADD(len_sec, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += len_sec + len_tmp;
    len_sec = len_tmp = 0;

    ASN1_CHK_ADD(len_sec, mbedtls_asn1_write_octet_string(&p, buf, hmac, 32));

    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_null(&p, buf));

    if (0 != mbedtls_oid_get_oid_by_md(MBEDTLS_MD_SHA256, &oid, &oid_len))
        return false;

    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));

    ASN1_CHK_ADD(len_sec, mbedtls_asn1_write_len(&p, buf, len_tmp));

    ASN1_CHK_ADD(len_sec, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len_sec, mbedtls_asn1_write_len(&p, buf, len_sec + len_tmp));

    ASN1_CHK_ADD(len_sec, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += len_sec + len_tmp;
    len_sec = len_tmp = 0;

    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_null(&p, buf));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_len(&p, buf, len_tmp));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_oid(&p, buf, (char *)additional_oid, sizeof(additional_oid)));

    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_len(&p, buf, len_tmp));
    ASN1_CHK_ADD(len_tmp, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    len += len_tmp;
    len_tmp = 0;

    p -= public_key_sz;
    memcpy(p, public_key, public_key_sz);

    len += public_key_sz;

    ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, buf, 0));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
#if 0
    char print_buf[1024];
    size_t print_buf_sz = 1024;
    mbedtls_base64_encode(print_buf, sizeof(print_buf), &print_buf_sz,
                          p, len);
    printf("\n\n%s\n", print_buf);
#endif

    *cryptogram_sz = len;

    if (len != buf_sz) {
        memmove(cryptogram, p, len);
    }

    return true;
}
