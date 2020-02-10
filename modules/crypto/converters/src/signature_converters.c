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

#include <string.h>
#include <stdbool.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>

#include <stdio.h>

#include <stdlib-config.h>

#include "private/macros.h"
#include <virgil/iot/converters/crypto_format_converters.h>
#include <virgil/iot/secmodule/secmodule.h>

/******************************************************************************/
static int
_coord_sz(vs_secmodule_keypair_type_e keypair_type) {
    switch (keypair_type) {
    case VS_KEYPAIR_EC_SECP192R1:
    case VS_KEYPAIR_EC_SECP192K1:
        return 24;
    case VS_KEYPAIR_EC_SECP224R1:
    case VS_KEYPAIR_EC_SECP224K1:
        return 28;
    case VS_KEYPAIR_EC_SECP256R1:
    case VS_KEYPAIR_EC_SECP256K1:
        return 32;
    case VS_KEYPAIR_EC_SECP384R1:
        return 48;
    case VS_KEYPAIR_EC_SECP521R1:
        return 66;
    case VS_KEYPAIR_EC_CURVE25519:
    case VS_KEYPAIR_EC_ED25519:
        return 32;
    default:
        return 0;
    }
}

/******************************************************************************/
static mbedtls_md_type_t
_secmodule_hash_to_mbedtls(vs_secmodule_hash_type_e hash_type) {
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

/*******************************************************************************/
static bool
_raw_ec_sign_to_mbedtls(vs_secmodule_keypair_type_e keypair_type,
                        const unsigned char *raw,
                        uint16_t raw_sz,
                        unsigned char *signature,
                        uint16_t buf_sz,
                        uint16_t *signature_sz) {
    int res = 0, ret, mbedtls_res;
    unsigned char *p = signature + buf_sz;
    uint16_t len = 0;
    const int component_sz = _coord_sz(keypair_type);
    mbedtls_mpi r, s;

    CHECK_BOOL_GOTO(buf_sz >= MBEDTLS_ECDSA_MAX_LEN, -1);

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    CHECK_BOOL_GOTO(raw_sz >= (component_sz * 2), -1);

    // Read r, s
    MBEDTLS_CHECK(mbedtls_mpi_read_binary(&r, raw, component_sz), -1);
    MBEDTLS_CHECK(mbedtls_mpi_read_binary(&s, &raw[component_sz], component_sz), -1);

    // Write r, s to ASN.1
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, signature, &s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, signature, &r));

    // Write ASN.1 sequence
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, signature, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, signature, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    VS_IOT_MEMMOVE(signature, p, len);
    *signature_sz = len;

terminate:

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return res == 0;
}

/*******************************************************************************/
bool
vs_converters_raw_sign_to_mbedtls(vs_secmodule_keypair_type_e keypair_type,
                                  const unsigned char *raw,
                                  uint16_t raw_sz,
                                  unsigned char *signature,
                                  uint16_t buf_sz,
                                  uint16_t *signature_sz) {
    bool res;

    VS_IOT_ASSERT(raw);
    VS_IOT_ASSERT(signature);
    VS_IOT_ASSERT(buf_sz);
    VS_IOT_ASSERT(signature_sz);

    NOT_ZERO(raw);
    NOT_ZERO(signature);
    NOT_ZERO(buf_sz);
    NOT_ZERO(signature_sz);

    if (keypair_type >= VS_KEYPAIR_EC_SECP_MIN && keypair_type <= VS_KEYPAIR_EC_SECP_MAX) {
        return _raw_ec_sign_to_mbedtls(keypair_type, raw, raw_sz, signature, buf_sz, signature_sz);
    }

    CHECK_BOOL_GOTO(buf_sz >= raw_sz, false);
    VS_IOT_MEMMOVE(signature, raw, raw_sz);
    *signature_sz = raw_sz;

    res = true;

terminate:

    return res;
}

/*******************************************************************************/
static bool
_mbedtls_sign_to_raw_ec(vs_secmodule_keypair_type_e keypair_type,
                        uint8_t *mbedtls_sign,
                        uint16_t mbedtls_sign_sz,
                        uint8_t *raw_sign,
                        uint16_t buf_sz,
                        uint16_t *raw_sz) {
    bool res = false;
    int mbedtls_res = 0;
    unsigned char *p = (unsigned char *)mbedtls_sign;
    const unsigned char *end = mbedtls_sign + mbedtls_sign_sz;
    size_t len;
    mbedtls_mpi r, s;
    const int component_sz = _coord_sz(keypair_type);

    if (buf_sz < component_sz * 2) {
        return false;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    MBEDTLS_CHECK(mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), false);

    if (p + len != end) {
        goto terminate;
    }

    MBEDTLS_CHECK(mbedtls_asn1_get_mpi(&p, end, &r), false);
    MBEDTLS_CHECK(mbedtls_asn1_get_mpi(&p, end, &s), false);

    // Save r, s to buffer
    MBEDTLS_CHECK(mbedtls_mpi_write_binary(&r, raw_sign, component_sz), false);
    MBEDTLS_CHECK(mbedtls_mpi_write_binary(&s, &raw_sign[component_sz], component_sz), false);

    *raw_sz = component_sz * 2;

    res = true;

terminate:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return res;
}

/******************************************************************************/
bool
vs_converters_mbedtls_sign_to_raw(vs_secmodule_keypair_type_e keypair_type,
                                  uint8_t *mbedtls_sign,
                                  uint16_t mbedtls_sign_sz,
                                  uint8_t *raw_sign,
                                  uint16_t buf_sz,
                                  uint16_t *raw_sz) {
    VS_IOT_ASSERT(raw_sz);
    VS_IOT_ASSERT(mbedtls_sign);
    VS_IOT_ASSERT(mbedtls_sign_sz);
    VS_IOT_ASSERT(raw_sign);
    VS_IOT_ASSERT(raw_sz);

    NOT_ZERO(raw_sz);
    NOT_ZERO(mbedtls_sign);
    NOT_ZERO(mbedtls_sign_sz);
    NOT_ZERO(raw_sign);
    NOT_ZERO(raw_sz);

    if (keypair_type >= VS_KEYPAIR_EC_SECP_MIN && keypair_type <= VS_KEYPAIR_EC_SECP_MAX) {
        return _mbedtls_sign_to_raw_ec(keypair_type, mbedtls_sign, mbedtls_sign_sz, raw_sign, buf_sz, raw_sz);
    }

    if (mbedtls_sign_sz > buf_sz) {
        return false;
    }

    VS_IOT_MEMMOVE(raw_sign, mbedtls_sign, mbedtls_sign_sz);
    *raw_sz = mbedtls_sign_sz;
    return true;
}

/******************************************************************************/
static bool
_virgil_sign_to_mbedtls(const uint8_t *virgil_sign, uint16_t virgil_sign_sz, const uint8_t **sign, uint16_t *sign_sz) {
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
static bool
_mbedtls_sign_to_virgil(vs_secmodule_hash_type_e hash_type,
                        uint8_t *mbedtls_sign,
                        uint16_t mbedtls_sign_sz,
                        uint8_t *virgil_sign,
                        uint16_t buf_sz,
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

    if (0 != mbedtls_oid_get_oid_by_md(_secmodule_hash_to_mbedtls(hash_type), &oid, &oid_len))
        return false;

    ASN1_CHK_ADD(hash_type_len, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, hash_type_len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len + hash_type_len));
    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += hash_type_len;

    if (buf_sz > len) {
        VS_IOT_MEMMOVE(virgil_sign, p, len);
    }

    *virgil_sign_sz = len;

    return true;
}

/******************************************************************************/
bool
vs_converters_virgil_sign_to_raw(vs_secmodule_keypair_type_e keypair_type,
                                 const uint8_t *virgil_sign,
                                 uint16_t virgil_sign_sz,
                                 uint8_t *sign,
                                 uint16_t buf_sz,
                                 uint16_t *sign_sz) {
    const uint8_t *p = NULL;
    uint16_t result_sz;

    VS_IOT_ASSERT(virgil_sign);
    VS_IOT_ASSERT(virgil_sign_sz);
    VS_IOT_ASSERT(sign);
    VS_IOT_ASSERT(buf_sz);
    VS_IOT_ASSERT(sign_sz);

    NOT_ZERO(virgil_sign);
    NOT_ZERO(virgil_sign_sz);
    NOT_ZERO(sign);
    NOT_ZERO(buf_sz);
    NOT_ZERO(sign_sz);

    if (!_virgil_sign_to_mbedtls(virgil_sign, virgil_sign_sz, &p, &result_sz) ||
        !vs_converters_mbedtls_sign_to_raw(keypair_type, (uint8_t *)p, result_sz, sign, buf_sz, sign_sz)) {
        return false;
    }

    return true;
}

/******************************************************************************/
bool
vs_converters_raw_sign_to_virgil(vs_secmodule_keypair_type_e keypair_type,
                                 vs_secmodule_hash_type_e hash_type,
                                 const uint8_t *raw_sign,
                                 uint16_t raw_sign_sz,
                                 uint8_t *virgil_sign,
                                 uint16_t buf_sz,
                                 uint16_t *virgil_sign_sz) {
    uint16_t result_sz;

    VS_IOT_ASSERT(raw_sign);
    VS_IOT_ASSERT(raw_sign_sz);
    VS_IOT_ASSERT(virgil_sign);
    VS_IOT_ASSERT(buf_sz);
    VS_IOT_ASSERT(virgil_sign_sz);

    NOT_ZERO(raw_sign);
    NOT_ZERO(raw_sign_sz);
    NOT_ZERO(virgil_sign);
    NOT_ZERO(buf_sz);
    NOT_ZERO(virgil_sign_sz);

    if (!vs_converters_raw_sign_to_mbedtls(keypair_type, raw_sign, raw_sign_sz, virgil_sign, buf_sz, &result_sz) ||
        !_mbedtls_sign_to_virgil(hash_type, virgil_sign, result_sz, virgil_sign, buf_sz, virgil_sign_sz)) {
        return false;
    }
    return true;
}
