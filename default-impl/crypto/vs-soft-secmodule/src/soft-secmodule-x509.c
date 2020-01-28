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
#include <stdint.h>

#include "private/vs-soft-secmodule-internal.h"

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/converters/crypto_format_converters.h>
#include <endian-config.h>

#include <mbedtls/pk_internal.h>
#include <mbedtls/oid.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

/******************************************************************************/
static void
_data_to_hex(const uint8_t *_data, uint32_t _len, uint8_t *_out_data, uint32_t *_in_out_len) {
    const uint8_t hex_str[] = "0123456789abcdef";

    VS_IOT_ASSERT(_data);
    VS_IOT_ASSERT(_out_data);
    VS_IOT_ASSERT(_in_out_len);
    VS_IOT_ASSERT(_len);
    VS_IOT_ASSERT(*_in_out_len >= _len * 2 + 1);

    VS_IOT_MEMSET(_out_data, 0, *_in_out_len);

    *_in_out_len = _len * 2 + 1;
    _out_data[*_in_out_len - 1] = 0;
    size_t i;

    for (i = 0; i < _len; i++) {
        _out_data[i * 2 + 0] = hex_str[(_data[i] >> 4) & 0x0F];
        _out_data[i * 2 + 1] = hex_str[(_data[i]) & 0x0F];
    }
}

// TODO: Do we need to use other parameters inside the certificate names?
#define VS_X509_CN_PREFIX "C=US,O=virgil,CN="

/********************************************************************************/
static vs_status_e
_x509_create_selfsign(const uint8_t *object_id,
                      uint16_t object_id_sz,
                      const char *not_before,
                      const char *not_after,
                      uint8_t *buf,
                      uint16_t buf_sz,
                      uint16_t *out_sz) {
    vs_status_e ret_code;
    int written;
    const char *pers = "x509";
    const vs_secmodule_impl_t *secmodule_impl = _soft_secmodule_intern();

    CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(out_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509write_cert crt;
    mbedtls_entropy_context entropy;
    mbedtls_pk_context issuer_prv_key_ctx;
    mbedtls_pk_context subj_pub_key_ctx;

    // create CN
    uint32_t cn_len = object_id_sz * 2 + 1;
    uint8_t object_id_str[cn_len];
    char cn_buf[cn_len + strlen(VS_X509_CN_PREFIX)];

    _data_to_hex(object_id, object_id_sz, object_id_str, &cn_len);
    VS_IOT_SNPRINTF(cn_buf, sizeof(cn_buf), "%s%s", VS_X509_CN_PREFIX, object_id_str);

    // Get the device's private and public keys
    vs_secmodule_keypair_type_e keypair_type;
    uint16_t private_key_sz;
    int32_t slot_sz = _get_slot_size(PRIVATE_KEY_SLOT);
    uint8_t private_key[slot_sz];
    STATUS_CHECK_RET(
            vs_secmodule_keypair_get_prvkey(PRIVATE_KEY_SLOT, private_key, slot_sz, &private_key_sz, &keypair_type),
            "Unable to load device private key");

    uint16_t subj_pubkey_sz = vs_secmodule_get_pubkey_len(keypair_type);
    uint8_t subj_pubkey[subj_pubkey_sz];
    STATUS_CHECK_RET(
            secmodule_impl->get_pubkey(PRIVATE_KEY_SLOT, subj_pubkey, subj_pubkey_sz, &subj_pubkey_sz, &keypair_type),
            "vs_secmodule_keypair_get_pubkey call error");

    // Init x509
    mbedtls_x509write_crt_init(&crt);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (!vs_soft_secmodule_create_context_for_private_key(
                &issuer_prv_key_ctx, (const unsigned char *)private_key, private_key_sz) ||
        !vs_soft_secmodule_create_context_for_public_key(
                &subj_pub_key_ctx, keypair_type, subj_pubkey, subj_pubkey_sz) ||
        0 != mbedtls_ctr_drbg_seed(
                     &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) ||
        0 != mbedtls_x509write_crt_set_issuer_name(&crt, cn_buf) ||
        0 != mbedtls_x509write_crt_set_subject_name(&crt, cn_buf) ||
        0 != mbedtls_x509write_crt_set_validity(&crt, not_before, not_after)) {
        ret_code = VS_CODE_ERR_CRYPTO;
        goto terminate;
    }

    // TODO: Do we need to use these functions?
    //    mbedtls_mpi serial;
    //    mbedtls_mpi_init(&serial);
    //    mbedtls_mpi_read_binary(&serial, (uint8_t *)&object_id, sizeof(object_id));

    //    if (0 != mbedtls_x509write_crt_set_authority_key_identifier(&crt) ||
    //        0 != mbedtls_x509write_crt_set_subject_key_identifier(&crt) ||
    //        0 != mbedtls_x509write_crt_set_serial(&crt, &serial)) {
    //        ret_code = VS_CODE_ERR_CRYPTO;
    //        goto terminate;
    //    }

    // TODO: What's version need?
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &subj_pub_key_ctx);
    mbedtls_x509write_crt_set_issuer_key(&crt, &issuer_prv_key_ctx);

    written = mbedtls_x509write_crt_der(&crt, buf, buf_sz, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (written < 0) {
        ret_code = VS_CODE_ERR_CRYPTO;
        goto terminate;
    }
    VS_IOT_MEMMOVE(buf, buf + (buf_sz - written), written);

    *out_sz = written;

terminate:
    mbedtls_x509write_crt_free(&crt);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&issuer_prv_key_ctx);
    mbedtls_pk_free(&subj_pub_key_ctx);
    //    mbedtls_mpi_free(&serial);

    return ret_code;
}

/********************************************************************************/
vs_status_e
_fill_x509_impl(vs_secmodule_impl_t *secmodule_impl) {
    CHECK_NOT_ZERO_RET(secmodule_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);

    secmodule_impl->x509_create_selfsign = _x509_create_selfsign;

    return VS_CODE_OK;
}
/********************************************************************************/
