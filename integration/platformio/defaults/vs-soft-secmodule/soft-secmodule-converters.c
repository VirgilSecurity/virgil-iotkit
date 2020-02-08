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

#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include <mbedtls/pk_internal.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>

#include <private/macros.h>
#include <virgil/iot/converters/crypto_format_converters.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <stdlib-config.h>

/******************************************************************************/
static uint16_t
_ec_mpi_size(vs_secmodule_keypair_type_e keypair_type) {
    int ec_size = vs_secmodule_get_signature_len(keypair_type);

    if(ec_size < 0) {
        return 0;
    }

    return ec_size / 2;
}

/******************************************************************************/
static mbedtls_ecp_group_id
_keypair_type_to_ecp_group_id(vs_secmodule_keypair_type_e keypair_type) {
    switch (keypair_type) {
    case VS_KEYPAIR_EC_SECP192R1:
        return MBEDTLS_ECP_DP_SECP192R1;
    case VS_KEYPAIR_EC_SECP224R1:
        return MBEDTLS_ECP_DP_SECP224R1;
    case VS_KEYPAIR_EC_SECP256R1:
        return MBEDTLS_ECP_DP_SECP256R1;
    case VS_KEYPAIR_EC_SECP384R1:
        return MBEDTLS_ECP_DP_SECP384R1;
    case VS_KEYPAIR_EC_SECP521R1:
        return MBEDTLS_ECP_DP_SECP521R1;
    case VS_KEYPAIR_EC_SECP192K1:
        return MBEDTLS_ECP_DP_SECP192K1;
    case VS_KEYPAIR_EC_SECP224K1:
        return MBEDTLS_ECP_DP_SECP224K1;
    case VS_KEYPAIR_EC_SECP256K1:
        return MBEDTLS_ECP_DP_SECP256K1;
    default:
        break;
    }

    return MBEDTLS_ECP_DP_NONE;
}

/******************************************************************************/
bool
vs_converters_pubkey_to_raw(vs_secmodule_keypair_type_e keypair_type,
                            const uint8_t *public_key,
                            uint16_t public_key_sz,
                            uint8_t *pubkey_raw,
                            uint16_t buf_sz,
                            uint16_t *pubkey_raw_sz) {
    uint8_t *p = (uint8_t *)public_key;
    uint8_t *end = p + public_key_sz;
    size_t len;
    mbedtls_asn1_bitstring bs;

    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    if (0 != mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return false;
    p += len;
    VS_IOT_MEMSET(&bs, 0, sizeof(mbedtls_asn1_bitstring));
    mbedtls_asn1_get_bitstring(&p, end, &bs);

    if (bs.len > buf_sz) {
        return false;
    }

    VS_IOT_MEMMOVE(pubkey_raw, bs.p, bs.len);
    *pubkey_raw_sz = bs.len;

    return true;
}

/******************************************************************************/
bool
vs_converters_pubkey_to_virgil(vs_secmodule_keypair_type_e keypair_type,
                               const uint8_t *public_key_in,
                               uint16_t public_key_in_sz,
                               uint8_t *public_key_out,
                               uint16_t buf_sz,
                               uint16_t *public_key_out_sz) {
    bool res = false;
    mbedtls_ecp_keypair ec_key;
    mbedtls_pk_info_t pk_info;
    mbedtls_pk_context pk_ctx;
    int mbedtls_res;

    size_t mpi_size;

    VS_IOT_ASSERT(public_key_in);
    VS_IOT_ASSERT(public_key_in_sz);
    VS_IOT_ASSERT(public_key_out);
    VS_IOT_ASSERT(buf_sz);
    VS_IOT_ASSERT(public_key_out_sz);

    CHECK_NOT_ZERO_RET(public_key_in, false);
    CHECK_NOT_ZERO_RET(public_key_in_sz, false);
    CHECK_NOT_ZERO_RET(public_key_out, false);
    CHECK_NOT_ZERO_RET(buf_sz, false);
    CHECK_NOT_ZERO_RET(public_key_out_sz, false);

    if (VS_KEYPAIR_EC_SECP_MIN > keypair_type || VS_KEYPAIR_EC_SECP_MAX < keypair_type) {
        return false;
    }

    VS_IOT_MEMSET(&ec_key, 0, sizeof(ec_key));
    VS_IOT_MEMSET(&pk_info, 0, sizeof(pk_info));
    VS_IOT_MEMSET(&pk_ctx, 0, sizeof(pk_ctx));

    pk_ctx.pk_info = &pk_info;
    pk_ctx.pk_ctx = &ec_key;

    pk_info.type = MBEDTLS_PK_ECKEY;
    MBEDTLS_CHECK(mbedtls_ecp_group_load(&ec_key.grp, _keypair_type_to_ecp_group_id(keypair_type)), false);

    mpi_size = _ec_mpi_size(keypair_type);

    if (!mpi_size || public_key_in_sz < mpi_size * 2 + 1) {
        return false;
    }

    if (0 == mbedtls_mpi_read_binary(&ec_key.Q.X, public_key_in + 1, mpi_size) &&
        0 == mbedtls_mpi_read_binary(&ec_key.Q.Y, public_key_in + 1 + mpi_size, mpi_size) &&
        0 == mbedtls_mpi_copy(&ec_key.Q.Z, &ec_key.Q.Y)) {

        mbedtls_res = mbedtls_pk_write_pubkey_der(&pk_ctx, public_key_out, buf_sz);

        if (mbedtls_res > 0 && buf_sz > mbedtls_res) {
            *public_key_out_sz = mbedtls_res;
            VS_IOT_MEMMOVE(public_key_out, &public_key_out[buf_sz - *public_key_out_sz], *public_key_out_sz);
            res = true;
        }
    }

terminate:
    mbedtls_ecp_keypair_free(&ec_key);

    return res;
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
    const uint16_t component_sz = _ec_mpi_size(keypair_type);
    mbedtls_mpi r, s;

    CHECK_NOT_ZERO_RET(component_sz, false);
    CHECK_BOOL_GOTO(buf_sz >= MBEDTLS_ECDSA_MAX_LEN, false);

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    CHECK_BOOL_GOTO(raw_sz >= (component_sz * 2), false);

    // Read r, s
    MBEDTLS_CHECK(mbedtls_mpi_read_binary(&r, raw, component_sz), false);
    MBEDTLS_CHECK(mbedtls_mpi_read_binary(&s, &raw[component_sz], component_sz), false);

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
    VS_IOT_ASSERT(raw);
    VS_IOT_ASSERT(signature);
    VS_IOT_ASSERT(buf_sz);
    VS_IOT_ASSERT(signature_sz);

    CHECK_NOT_ZERO_RET(raw, false);
    CHECK_NOT_ZERO_RET(signature, false);
    CHECK_NOT_ZERO_RET(buf_sz, false);
    CHECK_NOT_ZERO_RET(signature_sz, false);

    if (VS_KEYPAIR_EC_SECP_MIN > keypair_type || VS_KEYPAIR_EC_SECP_MAX < keypair_type) {
        return false;
    }

    return _raw_ec_sign_to_mbedtls(keypair_type, raw, raw_sz, signature, buf_sz, signature_sz);
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
    const uint16_t component_sz = _ec_mpi_size(keypair_type);

    CHECK_NOT_ZERO_RET(component_sz, false);
    
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
 
    if (VS_KEYPAIR_EC_SECP_MIN > keypair_type || VS_KEYPAIR_EC_SECP_MAX < keypair_type) {
        return false;
    }

    return _mbedtls_sign_to_raw_ec(keypair_type, mbedtls_sign, mbedtls_sign_sz, raw_sign, buf_sz, raw_sz);
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
