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
#include <mbedtls/pk_internal.h>
#include <mbedtls/oid.h>

#include <stdio.h>

#include <private/macros.h>
#include <virgil/iot/converters/crypto_format_converters.h>
#include <stdlib-config.h>

/******************************************************************************/
static uint16_t
_keypair_ec_mpi_size(vs_secmodule_keypair_type_e keypair_type) {
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

    default:
        break;
    }
    return 0;
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
static bool
_keypair_ec_key_to_internal(vs_secmodule_keypair_type_e keypair_type,
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

    VS_IOT_MEMSET(&ec_key, 0, sizeof(ec_key));
    VS_IOT_MEMSET(&pk_info, 0, sizeof(pk_info));
    VS_IOT_MEMSET(&pk_ctx, 0, sizeof(pk_ctx));

    pk_ctx.pk_info = &pk_info;
    pk_ctx.pk_ctx = &ec_key;

    pk_info.type = MBEDTLS_PK_ECKEY;
    MBEDTLS_CHECK(mbedtls_ecp_group_load(&ec_key.grp, _keypair_type_to_ecp_group_id(keypair_type)), false);

    mpi_size = _keypair_ec_mpi_size(keypair_type);

    if (public_key_in_sz < mpi_size * 2 + 1) {
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
static bool
_keypair_25519_key_to_internal(vs_secmodule_keypair_type_e keypair_type,
                               const uint8_t *public_key_in,
                               uint16_t public_key_in_sz,
                               uint8_t *public_key_out,
                               uint16_t buf_sz,
                               uint16_t *public_key_out_sz) {
    int res;
    mbedtls_fast_ec_keypair_t fast_ec_key;
    mbedtls_pk_info_t pk_info;
    mbedtls_pk_context pk_ctx;
    mbedtls_fast_ec_type_t type;

    VS_IOT_MEMSET(&fast_ec_key, 0, sizeof(fast_ec_key));
    VS_IOT_MEMSET(&pk_info, 0, sizeof(pk_info));
    VS_IOT_MEMSET(&pk_ctx, 0, sizeof(pk_ctx));

    pk_ctx.pk_info = &pk_info;
    pk_ctx.pk_ctx = &fast_ec_key;

    if (VS_KEYPAIR_EC_CURVE25519 == keypair_type) {
        pk_info.type = MBEDTLS_PK_X25519;
        type = MBEDTLS_FAST_EC_X25519;
    } else {
        pk_info.type = MBEDTLS_PK_ED25519;
        type = MBEDTLS_FAST_EC_ED25519;
    }

    fast_ec_key.info = mbedtls_fast_ec_info_from_type(type);
    fast_ec_key.public_key = (unsigned char *)public_key_in;

    res = mbedtls_pk_write_pubkey_der(&pk_ctx, public_key_out, buf_sz);
    if (res < 0 || buf_sz < res) {
        return false;
    }

    *public_key_out_sz = (uint16_t)res;

    if (buf_sz > *public_key_out_sz) {
        VS_IOT_MEMMOVE(public_key_out, &public_key_out[buf_sz - *public_key_out_sz], *public_key_out_sz);
    }

    return true;
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
    if (VS_KEYPAIR_EC_CURVE25519 == keypair_type || VS_KEYPAIR_EC_ED25519 == keypair_type) {
        return _keypair_25519_key_to_internal(
                keypair_type, public_key_in, public_key_in_sz, public_key_out, buf_sz, public_key_out_sz);
    } else {
        return _keypair_ec_key_to_internal(
                keypair_type, public_key_in, public_key_in_sz, public_key_out, buf_sz, public_key_out_sz);
    }
}
