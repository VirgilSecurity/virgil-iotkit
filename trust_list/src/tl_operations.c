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
#include <endian-config.h>

#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/private/tl_operations.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/hsm/hsm_sw_sha2_routines.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/provision/provision.h>

static vs_tl_context_t _tl_static_ctx;

static vs_tl_context_t _tl_dynamic_ctx;

static vs_tl_context_t _tl_tmp_ctx;

static const vs_key_type_e sign_rules_list[VS_TL_SIGNATURES_QTY] = VS_TL_SIGNER_TYPE_LIST;

/*************************************************************************/
static void
_create_data_filename(size_t storage_type, vs_tl_element_e el_id, size_t index, vs_storage_element_id_t file_id) {
    VS_IOT_ASSERT(sizeof(vs_storage_element_id_t) >= sizeof(storage_type) + sizeof(el_id) + sizeof(index));

    VS_IOT_MEMSET(file_id, 0, sizeof(vs_storage_element_id_t));
    VS_IOT_MEMCPY(&file_id[0], &storage_type, sizeof(storage_type));
    VS_IOT_MEMCPY(&file_id[sizeof(storage_type)], &el_id, sizeof(el_id));
    VS_IOT_MEMCPY(&file_id[sizeof(storage_type) + sizeof(el_id)], &index, sizeof(index));
}
/*************************************************************************/
static int
_read_data(const vs_storage_op_ctx_t *op_ctx,
           vs_storage_element_id_t id,
           uint32_t offset,
           uint8_t *data,
           uint16_t buff_sz,
           uint16_t *data_sz) {
    vs_storage_file_t f = NULL;
    int file_sz;
    CHECK_NOT_ZERO_RET(op_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.load, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.close, VS_STORAGE_ERROR_PARAMS);

    *data_sz = 0;
    file_sz = op_ctx->impl.size(op_ctx->storage_ctx, id);

    CHECK_RET(0 < file_sz, VS_STORAGE_ERROR_GENERAL, "Can't find file");
    CHECK_RET(file_sz >= offset + buff_sz, VS_STORAGE_ERROR_GENERAL, "File format error");

    f = op_ctx->impl.open(op_ctx->storage_ctx, id);
    CHECK_RET(NULL != f, VS_STORAGE_ERROR_GENERAL, "Can't open file");

    if (VS_STORAGE_OK != op_ctx->impl.load(op_ctx->storage_ctx, f, offset, data, buff_sz)) {
        VS_LOG_ERROR("Can't load data from file");
        op_ctx->impl.close(op_ctx->storage_ctx, f);
        return VS_STORAGE_ERROR_GENERAL;
    }
    *data_sz = buff_sz;
    return op_ctx->impl.close(op_ctx->storage_ctx, f);
}

/******************************************************************************/
static int
_write_data(const vs_storage_op_ctx_t *op_ctx,
            vs_storage_element_id_t id,
            uint32_t offset,
            const void *data,
            uint16_t data_sz) {
    vs_storage_file_t f = NULL;

    CHECK_NOT_ZERO_RET(op_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.del, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.save, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.close, VS_STORAGE_ERROR_PARAMS);
    CHECK_RET(data_sz <= op_ctx->file_sz_limit, VS_STORAGE_ERROR_PARAMS, "Requested size is too big");

    f = op_ctx->impl.open(op_ctx->storage_ctx, id);
    if (NULL == f) {
        VS_LOG_ERROR("Can't open file");
        return VS_STORAGE_ERROR_WRITE;
    }

    if (VS_STORAGE_OK != op_ctx->impl.save(op_ctx->storage_ctx, f, offset, data, data_sz)) {
        op_ctx->impl.close(op_ctx->storage_ctx, f);
        VS_LOG_ERROR("Can't save data to file");
        return VS_STORAGE_ERROR_WRITE;
    }

    return op_ctx->impl.close(op_ctx->storage_ctx, f);
}

/******************************************************************************/
static bool
_is_rule_equal_to(vs_key_type_e type) {
    uint8_t i;
    for (i = 0; i < VS_TL_SIGNATURES_QTY; ++i) {
        if (sign_rules_list[i] == type) {
            return true;
        }
    }
    return false;
}

/******************************************************************************/
static bool
_verify_tl(vs_tl_context_t *tl_ctx) {
    uint8_t buf[VS_TL_STORAGE_MAX_PART_SIZE];
    uint16_t res_sz;
    uint16_t i;
    vs_hsm_sw_sha256_ctx ctx;

    vs_tl_footer_t *footer;
    vs_sign_t *sign;
    uint8_t *pubkey;
    uint16_t sign_len;
    uint16_t key_len;
    uint8_t sign_rules = 0;
    vs_tl_header_t host_header;

    VS_IOT_MEMSET(buf, 0, sizeof(buf));

    // TODO: Need to support all hash types
    uint8_t hash[32];

    tl_ctx->ready = true;
    if (VS_STORAGE_OK != vs_tl_header_load(tl_ctx->storage.storage_type, &(tl_ctx->header))) {
        tl_ctx->ready = false;
        return false;
    }

    vs_tl_header_to_host(&(tl_ctx->header), &host_header);

    if (host_header.tl_size > VS_TL_STORAGE_SIZE) {
        tl_ctx->ready = false;
        return false;
    }

    vs_hsm_sw_sha256_init(&ctx);
    vs_hsm_sw_sha256_update(&ctx, (uint8_t *)&tl_ctx->header, sizeof(vs_tl_header_t));

    for (i = 0; i < host_header.pub_keys_count; ++i) {

        if (VS_STORAGE_OK != vs_tl_key_load(tl_ctx->storage.storage_type, i, buf, sizeof(buf), &res_sz)) {
            tl_ctx->ready = false;
            return false;
        }
        vs_hsm_sw_sha256_update(&ctx, buf, res_sz);
    }

    if (VS_STORAGE_OK != vs_tl_footer_load(tl_ctx->storage.storage_type, buf, sizeof(buf), &res_sz)) {
        tl_ctx->ready = false;
        return false;
    }

    footer = (vs_tl_footer_t *)buf;
    vs_hsm_sw_sha256_update(&ctx, (uint8_t *)&footer->tl_type, sizeof(footer->tl_type));
    vs_hsm_sw_sha256_final(&ctx, hash);

    // First signature
    sign = (vs_sign_t *)footer->signatures;

    BOOL_CHECK_RET(host_header.signatures_count >= VS_TL_SIGNATURES_QTY, "There are not enough signatures");

    for (i = 0; i < host_header.signatures_count; ++i) {
        BOOL_CHECK_RET(sign->hash_type == VS_HASH_SHA_256, "Unsupported hash size for sign TL");

        sign_len = vs_hsm_get_signature_len(sign->ec_type);
        key_len = vs_hsm_get_pubkey_len(sign->ec_type);

        BOOL_CHECK_RET(sign_len > 0 && key_len > 0, "Unsupported signature ec_type");
        ;

        // Signer raw key pointer
        pubkey = sign->raw_sign_pubkey + sign_len;

        BOOL_CHECK_RET(vs_provision_search_hl_pubkey(sign->signer_type, sign->ec_type, pubkey, key_len),
                       "Signer key is wrong");

        if (_is_rule_equal_to(sign->signer_type)) {
            BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_ecdsa_verify(sign->ec_type,
                                                                pubkey,
                                                                key_len,
                                                                sign->hash_type,
                                                                hash,
                                                                sign->raw_sign_pubkey,
                                                                sign_len),
                           "Signature is wrong");
            sign_rules++;
        }

        // Next signature
        sign = (vs_sign_t *)(pubkey + key_len);
    }

    VS_LOG_DEBUG("TL %u. Sign rules is %s",
                 tl_ctx->storage.storage_type,
                 sign_rules >= VS_TL_SIGNATURES_QTY ? "correct" : "wrong");

    return sign_rules >= VS_TL_SIGNATURES_QTY;
}

/******************************************************************************/
static void
_init_tl_ctx(size_t storage_type, const vs_storage_op_ctx_t *op_ctx, vs_tl_context_t *ctx) {
    if (!ctx)
        return;

    VS_IOT_MEMSET(ctx, 0, sizeof(vs_tl_context_t));
    ctx->storage.storage_type = storage_type;
    ctx->storage_ctx = op_ctx;
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
    vs_tl_header_t host_header;
    uint8_t buf[VS_TL_STORAGE_MAX_PART_SIZE];
    uint16_t res_sz;
    uint16_t i;

    if (!src->ready) {
        return VS_STORAGE_ERROR_GENERAL;
    }

    if (VS_STORAGE_OK != vs_tl_header_load(src->storage.storage_type, &header) ||
        VS_STORAGE_OK != vs_tl_header_save(dst->storage.storage_type, &header)) {
        dst->ready = false;
        return VS_STORAGE_ERROR_WRITE;
    }

    vs_tl_header_to_host(&header, &host_header);

    for (i = 0; i < host_header.pub_keys_count; ++i) {
        if (VS_STORAGE_OK != vs_tl_key_load(src->storage.storage_type, i, buf, sizeof(buf), &res_sz) ||
            VS_STORAGE_OK != vs_tl_key_save(dst->storage.storage_type, buf, res_sz)) {
            dst->ready = false;
            return VS_STORAGE_ERROR_WRITE;
        }
    }

    if (VS_STORAGE_OK != vs_tl_footer_load(src->storage.storage_type, buf, sizeof(buf), &res_sz) ||
        VS_STORAGE_OK != vs_tl_footer_save(dst->storage.storage_type, buf, res_sz)) {
        dst->ready = false;
        return VS_STORAGE_ERROR_WRITE;
    }

    dst->ready = true;
    dst->keys_qty.keys_amount = src->keys_qty.keys_amount;
    dst->keys_qty.keys_count = src->keys_qty.keys_count;

    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_verify_storage(size_t storage_type) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");

    if (!_verify_tl(tl_ctx)) {
        return VS_STORAGE_ERROR_GENERAL;
    }
    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_storage_init_internal(const vs_storage_op_ctx_t *op_ctx) {
    CHECK_NOT_ZERO_RET(op_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);

    _init_tl_ctx(TL_STORAGE_TYPE_DYNAMIC, op_ctx, &_tl_dynamic_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_STATIC, op_ctx, &_tl_static_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_TMP, op_ctx, &_tl_tmp_ctx);

    if (_verify_tl(&_tl_dynamic_ctx)) {
        return VS_STORAGE_OK;
    }

    if (_verify_tl(&_tl_static_ctx)) {
        if (VS_STORAGE_OK == _copy_tl_file(&_tl_dynamic_ctx, &_tl_static_ctx)) {
            return _verify_tl(&_tl_dynamic_ctx) ? VS_STORAGE_OK : VS_STORAGE_ERROR_GENERAL;
        }
    }

    return VS_STORAGE_ERROR_GENERAL;
}

/******************************************************************************/
int
vs_tl_storage_deinit_internal() {
    const vs_storage_op_ctx_t *op_ctx = _tl_dynamic_ctx.storage_ctx;

    CHECK_NOT_ZERO_RET(op_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(op_ctx->impl.deinit, VS_STORAGE_ERROR_PARAMS);


    VS_IOT_MEMSET(&_tl_dynamic_ctx, 0, sizeof(vs_tl_context_t));
    VS_IOT_MEMSET(&_tl_static_ctx, 0, sizeof(vs_tl_context_t));
    VS_IOT_MEMSET(&_tl_tmp_ctx, 0, sizeof(vs_tl_context_t));

    return op_ctx->impl.deinit(op_ctx->storage_ctx);
}

/******************************************************************************/
int
vs_tl_header_save(size_t storage_type, const vs_tl_header_t *header) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_tl_header_t host_header;
    vs_storage_element_id_t file_id;

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");
    CHECK_RET(NULL != header, VS_STORAGE_ERROR_PARAMS, "Invalid args");

    // Normalize byte order
    vs_tl_header_to_host(header, &host_header);

    CHECK_RET(host_header.tl_size <= VS_TL_STORAGE_SIZE,
              VS_STORAGE_ERROR_SMALL_BUFFER,
              "TL storage is too small for new TL");

    tl_ctx->ready = false;
    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = host_header.pub_keys_count;

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLH, 0, file_id);
    CHECK_RET(VS_STORAGE_OK == _write_data(tl_ctx->storage_ctx, file_id, 0, (uint8_t *)header, sizeof(vs_tl_header_t)),
              VS_STORAGE_ERROR_WRITE,
              "Error TL header save");

    VS_IOT_MEMCPY(&tl_ctx->header, header, sizeof(vs_tl_header_t));
    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_header_load(size_t storage_type, vs_tl_header_t *header) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_storage_element_id_t file_id;
    uint16_t _sz;

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");
    CHECK_RET(tl_ctx->ready, VS_STORAGE_ERROR_GENERAL, "TL Storage is not ready");

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLH, 0, file_id);
    CHECK_RET(VS_STORAGE_OK ==
                      _read_data(tl_ctx->storage_ctx, file_id, 0, (uint8_t *)header, sizeof(vs_tl_header_t), &_sz),
              VS_STORAGE_ERROR_READ,
              "Error TL header load");

    VS_IOT_MEMCPY(&tl_ctx->header, header, sizeof(vs_tl_header_t));
    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_footer_save(size_t storage_type, const uint8_t *footer, uint16_t footer_sz) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_storage_element_id_t file_id;

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");
    CHECK_RET(tl_ctx->keys_qty.keys_amount == tl_ctx->keys_qty.keys_count,
              VS_STORAGE_ERROR_PARAMS,
              "Keys amount is not equal");

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLF, 0, file_id);
    CHECK_RET(VS_STORAGE_OK == _write_data(tl_ctx->storage_ctx, file_id, 0, footer, footer_sz),
              VS_STORAGE_ERROR_WRITE,
              "Error TL footer save");

    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_footer_load(size_t storage_type, uint8_t *footer, uint16_t buf_sz, uint16_t *footer_sz) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    uint8_t buf[VS_TL_STORAGE_MAX_PART_SIZE];
    vs_storage_element_id_t file_id;

    // Pointer to first signature
    vs_sign_t *element = (vs_sign_t *)(buf + sizeof(vs_tl_footer_t));

    // Start determination of footer size
    uint16_t _sz = sizeof(vs_tl_footer_t);
    uint16_t read_sz;
    int sign_len;
    int key_len;
    uint8_t i;

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");
    CHECK_RET(NULL != footer && NULL != footer_sz, VS_STORAGE_ERROR_PARAMS, "Invalid args");
    CHECK_RET(tl_ctx->ready, VS_STORAGE_ERROR_GENERAL, "TL Storage is not ready");

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLF, 0, file_id);

    for (i = 0; i < tl_ctx->header.signatures_count; ++i) {

        // Add meta info size of current signature
        _sz += sizeof(vs_sign_t);

        CHECK_RET(VS_STORAGE_OK == _read_data(tl_ctx->storage_ctx, file_id, 0, buf, _sz, &read_sz),
                  VS_STORAGE_ERROR_READ,
                  "Error TL footer load");
        //        CHECK_RET(0 == vs_tl_load_hal(&el, buf, _sz), VS_STORAGE_ERROR_READ, "Error TL footer load");

        sign_len = vs_hsm_get_signature_len(element->ec_type);
        key_len = vs_hsm_get_pubkey_len(element->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_STORAGE_ERROR_READ, "Unsupported signature ec_type");

        // add the rest of vs_sign_t structure
        _sz += key_len + sign_len;

        // Pointer to the next signature
        element = (vs_sign_t *)((uint8_t *)element + sizeof(vs_sign_t) + key_len + sign_len);
    }

    CHECK_RET(buf_sz >= _sz, VS_STORAGE_ERROR_SMALL_BUFFER, "Out buffer too small");

    CHECK_RET(VS_STORAGE_OK == _read_data(tl_ctx->storage_ctx, file_id, 0, footer, _sz, &read_sz),
              VS_STORAGE_ERROR_READ,
              "Error TL footer load");
    //    CHECK_RET(0 == vs_tl_load_hal(&el, footer, _sz), VS_STORAGE_ERROR_READ, "Error TL footer load");

    *footer_sz = _sz;

    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_key_save(size_t storage_type, const uint8_t *key, uint16_t key_sz) {
    vs_pubkey_dated_t *element = (vs_pubkey_dated_t *)key;
    //    vs_tl_element_info_hal_t el = {storage_type, VS_TL_ELEMENT_TLC, 0};
    int key_len = vs_hsm_get_pubkey_len(element->pubkey.ec_type);
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_storage_element_id_t file_id;

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");
    CHECK_RET(key_len > 0, VS_STORAGE_ERROR_PARAMS, "Unsupported ec_type");
    CHECK_RET(element->pubkey.key_type < VS_KEY_UNSUPPORTED, VS_STORAGE_ERROR_PARAMS, "Invalid key type to save");

    key_len += sizeof(vs_pubkey_dated_t);

    CHECK_RET(key_len == key_sz, VS_STORAGE_ERROR_PARAMS, "Invalid length key to save");

    if (tl_ctx->keys_qty.keys_count >= tl_ctx->keys_qty.keys_amount) {
        tl_ctx->keys_qty.keys_count = tl_ctx->keys_qty.keys_amount;
        return VS_STORAGE_ERROR_WRITE;
    }

    //    el.index = tl_ctx->keys_qty.keys_count;
    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLC, tl_ctx->keys_qty.keys_count, file_id);
    if (VS_STORAGE_OK != _write_data(tl_ctx->storage_ctx, file_id, 0, key, key_sz)) {
        //    if (0 != vs_tl_save_hal(&el, key, key_sz)) {
        return VS_STORAGE_ERROR_WRITE;
    }

    tl_ctx->keys_qty.keys_count++;
    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_key_load(size_t storage_type, vs_tl_key_handle handle, uint8_t *key, uint16_t buf_sz, uint16_t *key_sz) {
    int key_len;
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_pubkey_dated_t element;
    //    vs_tl_element_info_hal_t el = {storage_type, VS_TL_ELEMENT_TLC, handle};
    vs_storage_element_id_t file_id;
    uint16_t _sz;

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");
    CHECK_RET(NULL != key && NULL != key_sz, VS_STORAGE_ERROR_PARAMS, "Invalid args");

    CHECK_RET(tl_ctx->ready, VS_STORAGE_ERROR_GENERAL, "TL Storage is not ready");

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLC, handle, file_id);

    // First, we need to load a meta info of required key to determine a full size
    CHECK_RET(VS_STORAGE_OK ==
                      _read_data(tl_ctx->storage_ctx, file_id, 0, (uint8_t *)&element, sizeof(vs_pubkey_dated_t), &_sz),
              VS_STORAGE_ERROR_READ,
              "Error TL key load");
    //    CHECK_RET(0 == vs_tl_load_hal(&el, (uint8_t *)&element, sizeof(vs_pubkey_dated_t)),
    //              VS_STORAGE_ERROR_READ,
    //              "Error TL key load");

    key_len = vs_hsm_get_pubkey_len(element.pubkey.ec_type);

    CHECK_RET(key_len > 0, VS_STORAGE_ERROR_READ, "Unsupported ec_type");

    // Full size of key stuff is raw key size and meta info
    key_len += sizeof(vs_pubkey_dated_t);

    CHECK_RET(key_len <= buf_sz, VS_STORAGE_ERROR_SMALL_BUFFER, "Out buffer too small");

    CHECK_RET(VS_STORAGE_OK == _read_data(tl_ctx->storage_ctx, file_id, 0, key, key_len, &_sz),
              VS_STORAGE_ERROR_READ,
              "Error TL key load");
    //    CHECK_RET(0 == vs_tl_load_hal(&el, key, key_len), VS_STORAGE_ERROR_READ, "Error TL key load");

    *key_sz = key_len;

    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_invalidate(size_t storage_type) {
    vs_tl_header_t header;
    //    vs_tl_element_info_hal_t el = {storage_type, VS_TL_ELEMENT_TLH, 0};

    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_storage_element_id_t file_id;
    uint16_t i;

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");
    CHECK_NOT_ZERO_RET(tl_ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(tl_ctx->storage_ctx->impl.del, VS_STORAGE_ERROR_PARAMS);

    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = 0;

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLH, 0, file_id);

    if (!tl_ctx->ready || VS_STORAGE_OK != vs_tl_header_load(storage_type, &header) ||
        (VS_STORAGE_OK != tl_ctx->storage_ctx->impl.del(tl_ctx->storage_ctx->storage_ctx, file_id))) {
        return VS_STORAGE_OK;
    }

    tl_ctx->ready = false;

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLF, 0, file_id);
    if (VS_STORAGE_OK != tl_ctx->storage_ctx->impl.del(tl_ctx->storage_ctx->storage_ctx, file_id)) {
        return VS_STORAGE_OK;
    }

    for (i = 0; i < header.pub_keys_count; ++i) {
        // cppcheck-suppress uninitvar
        _create_data_filename(storage_type, VS_TL_ELEMENT_TLC, i, file_id);
        if (VS_STORAGE_OK != tl_ctx->storage_ctx->impl.del(tl_ctx->storage_ctx->storage_ctx, file_id)) {
            return VS_STORAGE_OK;
        }
    }

    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_tl_apply_tmp_to(size_t storage_type) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    CHECK_RET(NULL != tl_ctx, VS_STORAGE_ERROR_PARAMS, "Invalid storage type");

    if (_verify_tl(&_tl_tmp_ctx)) {
        if (VS_STORAGE_OK != vs_tl_invalidate(storage_type)) {
            return VS_STORAGE_ERROR_GENERAL;
        }

        return _copy_tl_file(tl_ctx, &_tl_tmp_ctx);
    }

    return VS_STORAGE_ERROR_GENERAL;
}

/******************************************************************************/
void
vs_tl_header_to_host(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data) {
    *dst_data = *src_data;
    dst_data->pub_keys_count = VS_IOT_NTOHS(src_data->pub_keys_count);
    dst_data->tl_size = VS_IOT_NTOHL(src_data->tl_size);
    dst_data->version = VS_IOT_NTOHS(src_data->version);
}

/******************************************************************************/