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

#include <stdlib-config.h>
#include <logger-config.h>
#include <trust_list-config.h>

#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/private/tl_operations.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/hsm/hsm_sw_sha2_routines.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/provision/provision.h>

static vs_tl_context_t _tl_static_ctx;

static vs_tl_context_t _tl_dynamic_ctx;

static vs_tl_context_t _tl_tmp_ctx;

/******************************************************************************/
// static bool
//_verify_hash(vsc_buffer_t *hash,
//             vscf_alg_id_t hash_type,
//             uint8_t pub_key[PUBKEY_TINY_ID_SZ],
//             uint8_t sign[SIGNATURE_SZ]) {
//
//    const uint8_t *mbedtls_sign;
//    size_t mbedtls_sign_sz;
//
//    uint8_t full_public_key[VIRGIL_PUBLIC_KEY_MAX_SIZE];
//    size_t full_public_key_sz = VIRGIL_PUBLIC_KEY_MAX_SIZE;
//
//    uint8_t full_signature[VIRGIL_SIGNATURE_MAX_SIZE];
//    size_t full_signature_sz = VIRGIL_SIGNATURE_MAX_SIZE;
//
//    // TODO: we need to choose a suitable converter, which depends on the signature type
//    if (!tiny_nist256_pubkey_to_virgil((uint8_t *)public_key, full_public_key, &full_public_key_sz))
//        return false;
//    if (!tiny_nist256_sign_to_virgil((uint8_t *)signature, full_signature, &full_signature_sz))
//        return false;
//
//    return vs_converters_virgil_sign_to_mbedtls(full_signature, full_signature_sz, &mbedtls_sign, &mbedtls_sign_sz) &&
//           ecdsa_verify_with_internal_key(full_public_key,
//                                          full_public_key_sz,
//                                          hash_type,
//                                          hash,
//                                          (size_t)hash_size(hash_type),
//                                          mbedtls_sign,
//                                          mbedtls_sign_sz,
//                                          VS_SIGN_COMMON);
//}

/******************************************************************************/

// static bool
//_verify_tl_signature(vsc_buffer_t *hash,
//                     vscf_alg_id_t hash_type,
//                     iot_hsm_element_e el,
//                     crypto_signature_t *sign,
//                     vscf_alg_id_t sign_type) {
//    crypto_signed_hl_public_key_t key;
//    size_t read_sz;
//    vs_secbox_element_info_t info;
//    info.id = el;
//
//    for (size_t i = 0; i < PROVISION_KEYS_QTY; ++i) {
//        info.index = i;
//
//        if (VS_TL_OK == vs_secbox_load(&info, (uint8_t *)&key, sizeof(crypto_signed_hl_public_key_t), &read_sz) &&
//            key.public_key.id.key_id == sign->signer_id.key_id &&
//            keystorage_verify_hl_key_sign((uint8_t *)&key, sizeof(key))) {
//            if (_verify_hash(hash, hash_type, key.public_key.val, sign->val)) {
//                return true;
//            }
//        }
//    }
//    return false;
//}

/******************************************************************************/
// static bool
//_verify_tl_signatures(vsc_buffer_t *hash,
//                      vscf_alg_id_t hash_type,
//                      crypto_signature_t signs[TL_SIGNATURES_QTY],
//                      vscf_alg_id_t sign_type) {
//
//    if (!_verify_tl_signature(hash, hash_type, VS_SECBOX_ELEMENT_PBA, &signs[0], sign_type) ||
//        !_verify_tl_signature(hash, hash_type, IOT_HSM_ELEMENT_PBT, &signs[1], sign_type)) {
//        return false;
//    }
//    return true;
//}

/******************************************************************************/
static bool
_verify_tl(vs_tl_context_t *tl_ctx) {
    uint8_t buf[TL_STORAGE_MAX_PART_SIZE];
    uint16_t res_sz;
    uint16_t i;


    //    uint8_t buf[32];
    //    vscf_sha256_t hash_ctx;
    //    vsc_buffer_t hash;
    //
    tl_ctx->ready = true;
    if (VS_TL_OK != vs_tl_header_load(tl_ctx->storage.storage_type, &(tl_ctx->header))) {
        tl_ctx->ready = false;
        return false;
    }

    if (tl_ctx->header.tl_size > TL_STORAGE_SIZE) {
        tl_ctx->ready = false;
        return false;
    }
    //
    //    vscf_sha256_init(&hash_ctx);
    //    vsc_buffer_init(&hash);
    //    vsc_buffer_use(&hash, buf, sizeof(buf));
    //    vscf_sha256_start(&hash_ctx);
    //    vscf_sha256_update(&hash_ctx, vsc_data((uint8_t *)&header, sizeof(trust_list_header_t)));
    //
    for (i = 0; i < tl_ctx->header.pub_keys_count; ++i) {

        if (VS_TL_OK != vs_tl_key_load(tl_ctx->storage.storage_type, i, buf, sizeof(buf), &res_sz)) {
            tl_ctx->ready = false;
            return false;
        }
        //            vscf_sha256_update(&hash_ctx, vsc_data((uint8_t *)&key, sizeof(trust_list_pub_key_t)));
    }
    //
    //    vscf_sha256_finish(&hash_ctx, &hash);
    //
    bool res = (VS_TL_OK == vs_tl_footer_load(tl_ctx->storage.storage_type, buf, sizeof(buf), &res_sz) /*&&
                    _verify_tl_signatures(&hash, vscf_sha256_alg_id(&hash_ctx), &footer.auth_sign,
                    vscf_alg_id_SECP256R1)*/);
    if (!res) {
        tl_ctx->ready = false;
    }

    //
    //    vscf_sha256_cleanup(&hash_ctx);

    return true;
}

/******************************************************************************/
static void
_init_tl_ctx(size_t storage_type, vs_tl_context_t *ctx) {
    if (!ctx)
        return;

    memset(ctx, 0, sizeof(vs_tl_context_t));
    ctx->storage.storage_type = storage_type;
}

/******************************************************************************/
static vs_tl_context_t *
_get_tl_ctx(size_t storage_type) {
    switch (storage_type) {
    case TL_STORAGE_TYPE_STATIC:
        return &_tl_static_ctx;
    case TL_STORAGE_TYPE_DYNAMIC:
        return &_tl_dynamic_ctx;
    case TL_STORAGE_TYPE_TMP:
        return &_tl_tmp_ctx;
    default:
        break;
    }
    return NULL;
}

/******************************************************************************/
static int
_copy_tl_file(vs_tl_context_t *dst, vs_tl_context_t *src) {
    vs_tl_header_t header;
    uint8_t buf[TL_STORAGE_MAX_PART_SIZE];
    uint16_t res_sz;
    uint16_t i;

    if (!src->ready) {
        return VS_TL_ERROR_GENERAL;
    }

    if (VS_TL_OK != vs_tl_header_load(src->storage.storage_type, &header) ||
        VS_TL_OK != vs_tl_header_save(dst->storage.storage_type, &header)) {
        dst->ready = false;
        return VS_TL_ERROR_WRITE;
    }

    for (i = 0; i < header.pub_keys_count; ++i) {
        if (VS_TL_OK != vs_tl_key_load(src->storage.storage_type, i, buf, sizeof(buf), &res_sz) ||
            VS_TL_OK != vs_tl_key_save(dst->storage.storage_type, buf, res_sz)) {
            dst->ready = false;
            return VS_TL_ERROR_WRITE;
        }
    }

    if (VS_TL_OK != vs_tl_footer_load(src->storage.storage_type, buf, sizeof(buf), &res_sz) ||
        VS_TL_OK != vs_tl_footer_save(dst->storage.storage_type, buf, res_sz)) {
        dst->ready = false;
        return VS_TL_ERROR_WRITE;
    }

    dst->ready = true;
    dst->keys_qty.keys_amount = src->keys_qty.keys_amount;
    dst->keys_qty.keys_count = src->keys_qty.keys_count;

    return VS_TL_OK;
}

/******************************************************************************/
void
vs_tl_storage_init() {

    _init_tl_ctx(TL_STORAGE_TYPE_DYNAMIC, &_tl_dynamic_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_STATIC, &_tl_static_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_TMP, &_tl_tmp_ctx);

    if (!_verify_tl(&_tl_dynamic_ctx) && _verify_tl(&_tl_static_ctx)) {
        if (VS_TL_OK == _copy_tl_file(&_tl_dynamic_ctx, &_tl_static_ctx)) {
            _verify_tl(&_tl_dynamic_ctx);
        }
    }
}
/******************************************************************************/
int
vs_tl_header_save(size_t storage_type, const vs_tl_header_t *header) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_secbox_element_info_t el = {storage_type, VS_TL_ELEMENT_TLH, 0};

    CHECK_RET(NULL != tl_ctx, VS_TL_ERROR_PARAMS, "tl_ctx is NULL")
    CHECK_RET(NULL != header, VS_TL_ERROR_PARAMS, "Invalid args")
    CHECK_RET(header->tl_size <= TL_STORAGE_SIZE, VS_TL_ERROR_SMALL_BUFFER, "TL storage is too small for new TL")

    tl_ctx->ready = false;
    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = header->pub_keys_count;

    CHECK_RET(
            0 == vs_secbox_save(&el, (uint8_t *)header, sizeof(vs_tl_header_t)), VS_TL_ERROR_WRITE, "Error secbox load")

    memcpy(&tl_ctx->header, header, sizeof(vs_tl_header_t));
    return VS_TL_OK;
}

/******************************************************************************/
int
vs_tl_header_load(size_t storage_type, vs_tl_header_t *header) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_secbox_element_info_t el = {storage_type, VS_TL_ELEMENT_TLH, 0};

    CHECK_RET(NULL != tl_ctx, VS_TL_ERROR_PARAMS, "tl_ctx is NULL")
    CHECK_RET(tl_ctx->ready, VS_TL_ERROR_GENERAL, "TL Storage is not ready")

    CHECK_RET(
            0 == vs_secbox_load(&el, (uint8_t *)header, sizeof(vs_tl_header_t)), VS_TL_ERROR_READ, "Error secbox load")

    memcpy(&tl_ctx->header, header, sizeof(vs_tl_header_t));
    return VS_TL_OK;
}

/******************************************************************************/
int
vs_tl_footer_save(size_t storage_type, const uint8_t *footer, uint16_t footer_sz) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_secbox_element_info_t el = {storage_type, VS_TL_ELEMENT_TLF, 0};

    CHECK_RET(NULL != tl_ctx, VS_TL_ERROR_PARAMS, "tl_ctx is NULL")
    CHECK_RET(
            tl_ctx->keys_qty.keys_amount == tl_ctx->keys_qty.keys_count, VS_TL_ERROR_PARAMS, "Keys amount is not equal")

    CHECK_RET(0 == vs_secbox_save(&el, footer, footer_sz), VS_TL_ERROR_WRITE, "Error secbox write")

    return VS_TL_OK;
}

/******************************************************************************/
int
vs_tl_footer_load(size_t storage_type, uint8_t *footer, uint16_t buf_sz, uint16_t *footer_sz) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    uint8_t buf[TL_STORAGE_MAX_PART_SIZE];
    vs_sign_t *element = (vs_sign_t *)(buf + sizeof(vs_tl_footer_t));
    uint16_t _sz = sizeof(vs_tl_footer_t);
    int sign_len;
    int key_len;
    uint8_t i;

    vs_secbox_element_info_t el = {storage_type, VS_TL_ELEMENT_TLF, 0};

    CHECK_RET(NULL != tl_ctx, VS_TL_ERROR_PARAMS, "tl_ctx is NULL")
    CHECK_RET(NULL != footer && NULL != footer_sz, VS_TL_ERROR_PARAMS, "Invalid args")
    CHECK_RET(tl_ctx->ready, VS_TL_ERROR_GENERAL, "TL Storage is not ready")

    for (i = 0; i < tl_ctx->header.signatures_count; ++i) {
        _sz += sizeof(vs_sign_t);

        CHECK_RET(0 == vs_secbox_load(&el, buf, _sz), VS_TL_ERROR_READ, "Error secbox load")

        sign_len = vs_hsm_get_signature_len(element->ec_type);
        key_len = vs_hsm_get_pubkey_len(element->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_TL_ERROR_READ, "Unsupported signature ec_type");

        _sz += key_len + sign_len;

        element = (vs_sign_t *)((uint8_t *)element + sizeof(vs_sign_t) + key_len + sign_len);
    }

    CHECK_RET(buf_sz >= _sz, VS_TL_ERROR_SMALL_BUFFER, "Out buffer too small")

    CHECK_RET(0 == vs_secbox_load(&el, footer, _sz), VS_TL_ERROR_READ, "Error secbox load")

    *footer_sz = _sz;

    return VS_TL_OK;
}

/******************************************************************************/
int
vs_tl_key_save(size_t storage_type, const uint8_t *key, uint16_t key_sz) {
    vs_pubkey_dated_t *element = (vs_pubkey_dated_t *)key;
    vs_secbox_element_info_t el = {storage_type, VS_TL_ELEMENT_TLC, 0};
    int key_len = vs_hsm_get_pubkey_len(element->pubkey.ec_type);
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    CHECK_RET(NULL != tl_ctx, VS_TL_ERROR_PARAMS, "tl_ctx is NULL")
    CHECK_RET(key_len > 0, VS_TL_ERROR_PARAMS, "Unsupported ec_type")

    key_len += sizeof(vs_pubkey_dated_t);

    CHECK_RET(key_len == key_sz, VS_TL_ERROR_PARAMS, "Invalid length key to save")

    if (tl_ctx->keys_qty.keys_count >= tl_ctx->keys_qty.keys_amount) {
        tl_ctx->keys_qty.keys_count = tl_ctx->keys_qty.keys_amount;
        return VS_TL_ERROR_WRITE;
    }

    el.index = tl_ctx->keys_qty.keys_count;
    if (0 != vs_secbox_save(&el, key, key_sz)) {
        return VS_TL_ERROR_WRITE;
    }

    tl_ctx->keys_qty.keys_count++;
    return VS_TL_OK;
}

/******************************************************************************/
int
vs_tl_key_load(size_t storage_type, vs_tl_key_handle handle, uint8_t *key, uint16_t buf_sz, uint16_t *key_sz) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_pubkey_dated_t element;
    int key_len;
    vs_secbox_element_info_t el = {storage_type, VS_TL_ELEMENT_TLC, handle};

    CHECK_RET(NULL != tl_ctx, VS_TL_ERROR_PARAMS, "tl_ctx is NULL")
    CHECK_RET(NULL != key && NULL != key_sz, VS_TL_ERROR_PARAMS, "Invalid args")

    CHECK_RET(tl_ctx->ready, VS_TL_ERROR_GENERAL, "TL Storage is not ready")

    CHECK_RET(0 == vs_secbox_load(&el, (uint8_t *)&element, sizeof(vs_pubkey_dated_t)),
              VS_TL_ERROR_READ,
              "Error secbox load")

    key_len = vs_hsm_get_pubkey_len(element.pubkey.ec_type);

    CHECK_RET(key_len > 0, VS_TL_ERROR_READ, "Unsupported ec_type")

    key_len += sizeof(vs_pubkey_dated_t);

    CHECK_RET(key_len <= buf_sz, VS_TL_ERROR_SMALL_BUFFER, "Out buffer too small")

    CHECK_RET(0 == vs_secbox_load(&el, key, key_len), VS_TL_ERROR_READ, "Error secbox load")

    *key_sz = key_len;

    return VS_TL_OK;
}

/******************************************************************************/
int
vs_tl_invalidate(size_t storage_type) {
    vs_tl_header_t header;
    vs_secbox_element_info_t el = {storage_type, VS_TL_ELEMENT_TLH, 0};

    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    CHECK_RET(NULL != tl_ctx, VS_TL_ERROR_PARAMS, "tl_ctx is NULL")

    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = 0;

    if (!tl_ctx->ready || VS_TL_OK != vs_tl_header_load(storage_type, &header) || (0 != vs_secbox_del(&el))) {
        return VS_TL_OK;
    }

    tl_ctx->ready = false;

    el.id = VS_TL_ELEMENT_TLF;
    if (0 != vs_secbox_del(&el)) {
        return VS_TL_OK;
    }

    el.id = VS_TL_ELEMENT_TLC;
    for (el.index = 0; el.index < header.pub_keys_count; ++el.index) {
        if (0 != vs_secbox_del(&el)) {
            return VS_TL_OK;
        }
    }

    return VS_TL_OK;
}

/******************************************************************************/
int
vs_tl_apply_tmp_to(size_t storage_type) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    CHECK_RET(NULL != tl_ctx, VS_TL_ERROR_PARAMS, "tl_ctx is NULL")

    if (_verify_tl(&_tl_tmp_ctx)) {
        if (VS_TL_OK != vs_tl_invalidate(storage_type)) {
            return VS_TL_ERROR_GENERAL;
        }

        return _copy_tl_file(tl_ctx, &_tl_tmp_ctx);
    }

    return VS_TL_ERROR_GENERAL;
}

/******************************************************************************/
bool
vs_tl_verify_hl_key(const uint8_t *key_to_check, uint16_t key_size) {

    int key_len;
    int sign_len;
    int hash_size;
    uint16_t signed_data_sz;
    uint16_t res_sz;
    uint8_t *pubkey;

    BOOL_CHECK_RET(NULL != key_to_check, "Invalid args")
    BOOL_CHECK_RET(key_size > sizeof(vs_pubkey_dated_t), "key stuff is too small")

    vs_pubkey_dated_t *key = (vs_pubkey_dated_t *)key_to_check;

    if (VS_KEY_RECOVERY == key->pubkey.key_type) {
        return true;
    }

    key_len = vs_hsm_get_pubkey_len(key->pubkey.ec_type);

    BOOL_CHECK_RET(key_len > 0, "Unsupported key ec_type")

    signed_data_sz = sizeof(vs_pubkey_dated_t) + key_len;

    BOOL_CHECK_RET(key_size > signed_data_sz + sizeof(vs_sign_t), "key stuff is too small")

    vs_sign_t *sign = (vs_sign_t *)(key_to_check + signed_data_sz);
    sign_len = vs_hsm_get_signature_len(sign->ec_type);
    key_len = vs_hsm_get_pubkey_len(sign->ec_type);

    BOOL_CHECK_RET(sign_len > 0 && key_len > 0, "Unsupported signature ec_type");
    BOOL_CHECK_RET(key_size == signed_data_sz + sizeof(vs_sign_t) + sign_len + key_len, "key stuff is wrong")

    hash_size = vs_hsm_get_hash_len(sign->hash_type);
    BOOL_CHECK_RET(hash_size > 0, "Unsupported hash type")

    uint8_t hash[hash_size];

    VS_HSM_CHECK_RET(vs_hsm_hash_create(sign->hash_type, key_to_check, signed_data_sz, hash, hash_size, &res_sz),
                     "Error hash create")

    pubkey = sign->raw_sign_pubkey + sign_len;

    BOOL_CHECK_RET(vs_provision_search_hl_pubkey(sign->signer_type, sign->ec_type, pubkey, key_len),
                   "Signer key is wrong")

    VS_HSM_CHECK_RET(
            vs_hsm_ecdsa_verify(sign->ec_type, pubkey, key_len, sign->hash_type, hash, sign->raw_sign_pubkey, sign_len),
            "Signature is wrong")

    return true;
}
