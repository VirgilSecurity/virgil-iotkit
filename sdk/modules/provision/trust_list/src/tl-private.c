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

#include <stdlib-config.h>
#include <trust_list-config.h>
#include <endian-config.h>

#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/provision/provision.h>

#include "private/tl-private.h"

static vs_tl_context_t _tl_static_ctx;

static vs_tl_context_t _tl_dynamic_ctx;

static vs_tl_context_t _tl_tmp_ctx;

static const vs_key_type_e sign_rules_list[VS_TL_SIGNATURES_QTY] = VS_TL_SIGNER_TYPE_LIST;

static vs_secmodule_impl_t *_secmodule = NULL;

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
static vs_status_e
_read_data(const vs_storage_op_ctx_t *op_ctx,
           vs_storage_element_id_t id,
           uint32_t offset,
           uint8_t *data,
           uint16_t buff_sz,
           uint16_t *data_sz) {
    vs_storage_file_t f = NULL;
    ssize_t file_sz;
    CHECK_NOT_ZERO_RET(op_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.open, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.load, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.close, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *data_sz = 0;
    file_sz = op_ctx->impl_func.size(op_ctx->impl_data, id);

    CHECK_RET(0 < file_sz, VS_CODE_ERR_NOT_FOUND, "Can't find file");
    CHECK_RET(file_sz >= offset + buff_sz, VS_CODE_ERR_FILE, "File format error");

    f = op_ctx->impl_func.open(op_ctx->impl_data, id);
    CHECK_RET(NULL != f, VS_CODE_ERR_FILE, "Can't open file");

    if (VS_CODE_OK != op_ctx->impl_func.load(op_ctx->impl_data, f, offset, data, buff_sz)) {
        VS_LOG_ERROR("Can't load data from file");
        op_ctx->impl_func.close(op_ctx->impl_data, f);
        return VS_CODE_ERR_FILE_READ;
    }
    *data_sz = buff_sz;
    return op_ctx->impl_func.close(op_ctx->impl_data, f);
}

/******************************************************************************/
static vs_status_e
_write_data(const vs_storage_op_ctx_t *op_ctx,
            vs_storage_element_id_t id,
            uint32_t offset,
            const void *data,
            uint16_t data_sz) {
    vs_storage_file_t f = NULL;

    CHECK_NOT_ZERO_RET(op_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.del, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.open, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.save, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.sync, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.close, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(data_sz <= op_ctx->file_sz_limit, VS_CODE_ERR_NULLPTR_ARGUMENT, "Requested size is too big");

    f = op_ctx->impl_func.open(op_ctx->impl_data, id);
    if (NULL == f) {
        VS_LOG_ERROR("Can't open file");
        return VS_CODE_ERR_FILE;
    }

    if (VS_CODE_OK != op_ctx->impl_func.save(op_ctx->impl_data, f, offset, data, data_sz)) {
        op_ctx->impl_func.close(op_ctx->impl_data, f);
        VS_LOG_ERROR("Can't save data to file");
        return VS_CODE_ERR_FILE_WRITE;
    }

    int res = op_ctx->impl_func.sync(op_ctx->impl_data, f);
    CHECK_RET(VS_CODE_OK == res, res, "Can't sync file");

    return op_ctx->impl_func.close(op_ctx->impl_data, f);
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
    vs_secmodule_sw_sha256_ctx ctx;

    vs_tl_footer_t *footer;
    vs_sign_t *sign;
    uint8_t *pubkey;
    int sign_len;
    int key_len;
    uint8_t sign_rules = 0;
    vs_tl_header_t host_header;

    VS_IOT_ASSERT(_secmodule);
    VS_IOT_ASSERT(_secmodule->hash_init);
    VS_IOT_ASSERT(_secmodule->hash_update);
    VS_IOT_ASSERT(_secmodule->hash_finish);

    VS_IOT_MEMSET(buf, 0, sizeof(buf));

    // TODO: Need to support all hash types
    uint8_t hash[VS_HASH_SHA256_LEN];

    tl_ctx->ready = true;
    if (VS_CODE_OK != vs_tl_header_load(tl_ctx->storage.storage_type, &(tl_ctx->header))) {
        tl_ctx->ready = false;
        return false;
    }

    vs_tl_header_to_host(&(tl_ctx->header), &host_header);

    if (host_header.tl_size > VS_TL_STORAGE_SIZE) {
        tl_ctx->ready = false;
        return false;
    }

    _secmodule->hash_init(&ctx);
    _secmodule->hash_update(&ctx, (uint8_t *)&tl_ctx->header, sizeof(vs_tl_header_t));

    for (i = 0; i < host_header.pub_keys_count; ++i) {

        if (VS_CODE_OK != vs_tl_key_load(tl_ctx->storage.storage_type, i, buf, sizeof(buf), &res_sz)) {
            tl_ctx->ready = false;
            return false;
        }
        _secmodule->hash_update(&ctx, buf, res_sz);
    }

    if (VS_CODE_OK != vs_tl_footer_load(tl_ctx->storage.storage_type, buf, sizeof(buf), &res_sz)) {
        tl_ctx->ready = false;
        return false;
    }

    footer = (vs_tl_footer_t *)buf;
    _secmodule->hash_update(&ctx, (uint8_t *)&footer->tl_type, sizeof(footer->tl_type));
    _secmodule->hash_finish(&ctx, hash);

    // First signature
    sign = (vs_sign_t *)footer->signatures;

    BOOL_CHECK_RET(host_header.signatures_count >= VS_TL_SIGNATURES_QTY, "There are not enough signatures");

    for (i = 0; i < host_header.signatures_count; ++i) {
        BOOL_CHECK_RET(sign->hash_type == VS_HASH_SHA_256, "Unsupported hash size for sign TL");

        sign_len = vs_secmodule_get_signature_len(sign->ec_type);
        key_len = vs_secmodule_get_pubkey_len(sign->ec_type);

        BOOL_CHECK_RET(sign_len > 0 && key_len > 0, "Unsupported signature ec_type");

        // Signer raw key pointer
        pubkey = sign->raw_sign_pubkey + (uint16_t)sign_len;

        BOOL_CHECK_RET(VS_CODE_OK == vs_provision_search_hl_pubkey(
                                             sign->signer_type, sign->ec_type, pubkey, (uint16_t)key_len),
                       "Signer key is wrong");

        if (_is_rule_equal_to(sign->signer_type)) {
            BOOL_CHECK_RET(VS_CODE_OK == _secmodule->ecdsa_verify(sign->ec_type,
                                                                  pubkey,
                                                                  (uint16_t)key_len,
                                                                  sign->hash_type,
                                                                  hash,
                                                                  sign->raw_sign_pubkey,
                                                                  (uint16_t)sign_len),
                           "Signature is wrong");
            sign_rules++;
        }

        // Next signature
        sign = (vs_sign_t *)(pubkey + (uint16_t)key_len);
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
static vs_status_e
_copy_tl_file(vs_tl_context_t *dst, vs_tl_context_t *src) {
    vs_tl_header_t header;
    vs_tl_header_t host_header;
    uint8_t buf[VS_TL_STORAGE_MAX_PART_SIZE];
    uint16_t res_sz;
    uint16_t i;

    if (!src->ready) {
        return VS_CODE_ERR_CTX_NOT_READY;
    }

    if (VS_CODE_OK != vs_tl_header_load(src->storage.storage_type, &header) ||
        VS_CODE_OK != vs_tl_header_save(dst->storage.storage_type, &header)) {
        dst->ready = false;
        return VS_CODE_ERR_FILE_WRITE;
    }

    vs_tl_header_to_host(&header, &host_header);

    for (i = 0; i < host_header.pub_keys_count; ++i) {
        if (VS_CODE_OK != vs_tl_key_load(src->storage.storage_type, i, buf, sizeof(buf), &res_sz) ||
            VS_CODE_OK != vs_tl_key_save(dst->storage.storage_type, buf, res_sz)) {
            dst->ready = false;
            return VS_CODE_ERR_FILE_WRITE;
        }
    }

    if (VS_CODE_OK != vs_tl_footer_load(src->storage.storage_type, buf, sizeof(buf), &res_sz) ||
        VS_CODE_OK != vs_tl_footer_save(dst->storage.storage_type, buf, res_sz)) {
        dst->ready = false;
        return VS_CODE_ERR_FILE_WRITE;
    }

    dst->ready = true;
    dst->keys_qty.keys_amount = src->keys_qty.keys_amount;
    dst->keys_qty.keys_count = src->keys_qty.keys_count;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_tl_verify_storage(size_t storage_type) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");

    if (!_verify_tl(tl_ctx)) {
        return VS_CODE_ERR_VERIFY;
    }
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_tl_storage_init_internal(vs_storage_op_ctx_t *op_ctx, vs_secmodule_impl_t *secmodule) {
    CHECK_NOT_ZERO_RET(op_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);

    _secmodule = secmodule;

    vs_update_trust_list_init(op_ctx);

    _init_tl_ctx(TL_STORAGE_TYPE_DYNAMIC, op_ctx, &_tl_dynamic_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_STATIC, op_ctx, &_tl_static_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_TMP, op_ctx, &_tl_tmp_ctx);

    if (_verify_tl(&_tl_dynamic_ctx)) {
        return VS_CODE_OK;
    }

    if (_verify_tl(&_tl_static_ctx)) {
        vs_status_e ret_code = _copy_tl_file(&_tl_dynamic_ctx, &_tl_static_ctx);
        if (VS_CODE_OK == ret_code) {
            return _verify_tl(&_tl_dynamic_ctx) ? VS_CODE_OK : VS_CODE_ERR_VERIFY;
        }
        return ret_code;
    }

    return VS_CODE_ERR_NOINIT;
}

/******************************************************************************/
vs_status_e
vs_tl_storage_deinit_internal() {
    const vs_storage_op_ctx_t *op_ctx = _tl_dynamic_ctx.storage_ctx;

    CHECK_NOT_ZERO_RET(op_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(op_ctx->impl_func.deinit, VS_CODE_ERR_NULLPTR_ARGUMENT);


    VS_IOT_MEMSET(&_tl_dynamic_ctx, 0, sizeof(vs_tl_context_t));
    VS_IOT_MEMSET(&_tl_static_ctx, 0, sizeof(vs_tl_context_t));
    VS_IOT_MEMSET(&_tl_tmp_ctx, 0, sizeof(vs_tl_context_t));

    return op_ctx->impl_func.deinit(op_ctx->impl_data);
}

/******************************************************************************/
vs_status_e
vs_tl_header_save(size_t storage_type, const vs_tl_header_t *header) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_tl_header_t host_header;
    vs_storage_element_id_t file_id;

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");
    CHECK_RET(NULL != header, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid args");

    // Normalize byte order
    vs_tl_header_to_host(header, &host_header);

    CHECK_RET(host_header.tl_size <= VS_TL_STORAGE_SIZE,
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "TL storage is too small for new TL");

    tl_ctx->ready = false;
    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = host_header.pub_keys_count;

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLH, 0, file_id);
    CHECK_RET(VS_CODE_OK == _write_data(tl_ctx->storage_ctx, file_id, 0, (uint8_t *)header, sizeof(vs_tl_header_t)),
              VS_CODE_ERR_FILE_WRITE,
              "Error TL header save");

    VS_IOT_MEMCPY(&tl_ctx->header, header, sizeof(vs_tl_header_t));
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_tl_header_load(size_t storage_type, vs_tl_header_t *header) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_storage_element_id_t file_id;
    uint16_t _sz;

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");
    CHECK_RET(tl_ctx->ready, VS_CODE_ERR_NULLPTR_ARGUMENT, "TL Storage is not ready");

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLH, 0, file_id);
    CHECK_RET(VS_CODE_OK ==
                      _read_data(tl_ctx->storage_ctx, file_id, 0, (uint8_t *)header, sizeof(vs_tl_header_t), &_sz),
              VS_CODE_ERR_FILE_READ,
              "Error TL header load");

    VS_IOT_MEMCPY(&tl_ctx->header, header, sizeof(vs_tl_header_t));
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_tl_footer_save(size_t storage_type, const uint8_t *footer, uint16_t footer_sz) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_storage_element_id_t file_id;

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");
    CHECK_RET(tl_ctx->keys_qty.keys_amount == tl_ctx->keys_qty.keys_count,
              VS_CODE_ERR_INCORRECT_PARAMETER,
              "Keys amount is not equal");
    CHECK_RET(footer_sz <= tl_ctx->storage_ctx->file_sz_limit, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect key size");

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLF, 0, file_id);
    CHECK_RET(VS_CODE_OK == _write_data(tl_ctx->storage_ctx, file_id, 0, footer, footer_sz),
              VS_CODE_ERR_FILE_WRITE,
              "Error TL footer save");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
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

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");
    CHECK_RET(NULL != footer && NULL != footer_sz, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid args");
    CHECK_RET(tl_ctx->ready, VS_CODE_ERR_NULLPTR_ARGUMENT, "TL Storage is not ready");

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLF, 0, file_id);

    for (i = 0; i < tl_ctx->header.signatures_count; ++i) {

        // Add meta info size of current signature
        _sz += sizeof(vs_sign_t);

        CHECK_RET(VS_CODE_OK == _read_data(tl_ctx->storage_ctx, file_id, 0, buf, _sz, &read_sz),
                  VS_CODE_ERR_FILE_READ,
                  "Error TL footer load");

        sign_len = vs_secmodule_get_signature_len(element->ec_type);
        key_len = vs_secmodule_get_pubkey_len(element->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_CODE_ERR_FILE_READ, "Unsupported signature ec_type");

        // add the rest of vs_sign_t structure
        _sz += key_len + sign_len;

        // Pointer to the next signature
        element = (vs_sign_t *)((uint8_t *)element + sizeof(vs_sign_t) + key_len + sign_len);
    }

    CHECK_RET(buf_sz >= _sz, VS_CODE_ERR_TOO_SMALL_BUFFER, "Out buffer too small");

    CHECK_RET(VS_CODE_OK == _read_data(tl_ctx->storage_ctx, file_id, 0, footer, _sz, &read_sz),
              VS_CODE_ERR_FILE_READ,
              "Error TL footer load");

    *footer_sz = _sz;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_tl_key_save(size_t storage_type, const uint8_t *key, uint16_t key_sz) {
    vs_pubkey_dated_t *element = (vs_pubkey_dated_t *)key;
    int key_len = vs_secmodule_get_pubkey_len(element->pubkey.ec_type);
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_storage_element_id_t file_id;

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");
    CHECK_RET(key_len > 0, VS_CODE_ERR_INCORRECT_PARAMETER, "Unsupported ec_type");
    CHECK_RET(
            element->pubkey.key_type < VS_KEY_UNSUPPORTED, VS_CODE_ERR_INCORRECT_PARAMETER, "Invalid key type to save");
    CHECK_RET(key_sz <= tl_ctx->storage_ctx->file_sz_limit, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect key size");

    key_len += sizeof(vs_pubkey_dated_t) + VS_IOT_NTOHS(element->pubkey.meta_data_sz);

    CHECK_RET(key_len == key_sz, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect key size");

    if (tl_ctx->keys_qty.keys_count >= tl_ctx->keys_qty.keys_amount) {
        tl_ctx->keys_qty.keys_count = tl_ctx->keys_qty.keys_amount;
        return VS_CODE_ERR_FILE_WRITE;
    }

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLC, tl_ctx->keys_qty.keys_count, file_id);
    if (VS_CODE_OK != _write_data(tl_ctx->storage_ctx, file_id, 0, key, key_sz)) {
        return VS_CODE_ERR_FILE_WRITE;
    }

    tl_ctx->keys_qty.keys_count++;
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_tl_key_load(size_t storage_type, vs_tl_key_handle handle, uint8_t *key, uint16_t buf_sz, uint16_t *key_sz) {
    int key_len;
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_pubkey_dated_t element;
    vs_storage_element_id_t file_id;
    uint16_t _sz;

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");
    CHECK_RET(NULL != key && NULL != key_sz, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid args");

    CHECK_RET(tl_ctx->ready, VS_CODE_ERR_NULLPTR_ARGUMENT, "TL Storage is not ready");

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLC, handle, file_id);

    // First, we need to load a meta info of required key to determine a full size
    CHECK_RET(VS_CODE_OK ==
                      _read_data(tl_ctx->storage_ctx, file_id, 0, (uint8_t *)&element, sizeof(vs_pubkey_dated_t), &_sz),
              VS_CODE_ERR_FILE_READ,
              "Error TL key load");

    key_len = vs_secmodule_get_pubkey_len(element.pubkey.ec_type);

    CHECK_RET(key_len > 0, VS_CODE_ERR_FILE_READ, "Unsupported ec_type");

    // Full size of key stuff is raw key size and meta info
    key_len += sizeof(vs_pubkey_dated_t) + VS_IOT_NTOHS(element.pubkey.meta_data_sz);

    CHECK_RET(key_len <= buf_sz, VS_CODE_ERR_TOO_SMALL_BUFFER, "Out buffer too small");

    CHECK_RET(VS_CODE_OK == _read_data(tl_ctx->storage_ctx, file_id, 0, key, key_len, &_sz),
              VS_CODE_ERR_FILE_READ,
              "Error TL key load");

    *key_sz = key_len;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_tl_invalidate(size_t storage_type) {
    vs_tl_header_t header;

    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);
    vs_storage_element_id_t file_id;
    uint16_t i;

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");
    CHECK_NOT_ZERO_RET(tl_ctx->storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(tl_ctx->storage_ctx->impl_func.del, VS_CODE_ERR_NULLPTR_ARGUMENT);

    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = 0;

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLH, 0, file_id);

    if (!tl_ctx->ready || VS_CODE_OK != vs_tl_header_load(storage_type, &header) ||
        (VS_CODE_OK != tl_ctx->storage_ctx->impl_func.del(tl_ctx->storage_ctx->impl_data, file_id))) {
        return VS_CODE_OK;
    }

    tl_ctx->ready = false;

    // cppcheck-suppress uninitvar
    _create_data_filename(storage_type, VS_TL_ELEMENT_TLF, 0, file_id);
    if (VS_CODE_OK != tl_ctx->storage_ctx->impl_func.del(tl_ctx->storage_ctx->impl_data, file_id)) {
        return VS_CODE_OK;
    }

    for (i = 0; i < VS_IOT_NTOHS(header.pub_keys_count); ++i) {
        // cppcheck-suppress uninitvar
        _create_data_filename(storage_type, VS_TL_ELEMENT_TLC, i, file_id);
        if (VS_CODE_OK != tl_ctx->storage_ctx->impl_func.del(tl_ctx->storage_ctx->impl_data, file_id)) {
            return VS_CODE_OK;
        }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_tl_apply_tmp_to(size_t storage_type) {
    vs_tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    CHECK_RET(NULL != tl_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT, "Invalid storage type");

    if (_verify_tl(&_tl_tmp_ctx)) {
        if (VS_CODE_OK != vs_tl_invalidate(storage_type)) {
            return VS_CODE_ERR_VERIFY;
        }

        return _copy_tl_file(tl_ctx, &_tl_tmp_ctx);
    }

    return VS_CODE_ERR_FILE;
}

/******************************************************************************/