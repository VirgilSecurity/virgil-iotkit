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

#include "vs_tl_structs.h"
#include "private/vs_tl_files_impl.h"
#include "private/vs_tl_operations.h"
#include "secbox.h"

static tl_context_t _tl_static_ctx;

static tl_context_t _tl_dynamic_ctx;

static tl_context_t _tl_tmp_ctx;

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
//    return virgil_sign_to_mbedtls(full_signature, full_signature_sz, &mbedtls_sign, &mbedtls_sign_sz) &&
//           ecdsa_verify_with_internal_key(full_public_key,
//                                          full_public_key_sz,
//                                          hash_type,
//                                          hash,
//                                          (size_t)hash_size(hash_type),
//                                          mbedtls_sign,
//                                          mbedtls_sign_sz,
//                                          SIGN_COMMON);
//}

/******************************************************************************/

// static bool
//_verify_tl_signature(vsc_buffer_t *hash,
//                     vscf_alg_id_t hash_type,
//                     vs_secbox_element_e el,
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
//        if (TL_OK == vs_secbox_load(&info, (uint8_t *)&key, sizeof(crypto_signed_hl_public_key_t), &read_sz) &&
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
//        !_verify_tl_signature(hash, hash_type, VS_SECBOX_ELEMENT_PBT, &signs[1], sign_type)) {
//        return false;
//    }
//    return true;
//}

/******************************************************************************/
static bool
_verify_tl(tl_context_t *tl_ctx) {
        trust_list_header_t header;
        trust_list_pub_key_t key;
        trust_list_footer_t footer;
        uint16_t i;


    //    uint8_t buf[32];
    //    vscf_sha256_t hash_ctx;
    //    vsc_buffer_t hash;
    //
        tl_ctx->ready = true;
        if (TL_OK != load_tl_header(tl_ctx->storage.storage_type, &header)) {
            tl_ctx->ready = false;
            return false;
        }

        uint32_t tl_size = header.pub_keys_count * sizeof(trust_list_pub_key_t) + sizeof(trust_list_header_t) +
                           sizeof(trust_list_footer_t);

        if (header.tl_size > TL_STORAGE_SIZE || header.tl_size != tl_size) {
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
        for (i = 0; i < header.pub_keys_count; ++i) {

            if (TL_OK != load_tl_key(tl_ctx->storage.storage_type, i, &key)) {
                tl_ctx->ready = false;
                return false;
            }
//            vscf_sha256_update(&hash_ctx, vsc_data((uint8_t *)&key, sizeof(trust_list_pub_key_t)));
        }
    //
    //    vscf_sha256_finish(&hash_ctx, &hash);
    //
        bool res = (TL_OK == load_tl_footer(tl_ctx->storage.storage_type, &footer) /*&&
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
_init_tl_ctx(size_t storage_type, tl_context_t *ctx) {
    if (!ctx)
        return;

    memset(&ctx->keys_qty, 0, sizeof(tl_keys_qty_t));
    ctx->ready = false;
    ctx->storage.storage_type = storage_type;
    ctx->storage.addr = get_tl_default_base_addr_impl(storage_type);
}

/******************************************************************************/
static tl_context_t *
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
_copy_tl_file(tl_context_t *dst, tl_context_t *src) {
    trust_list_header_t header;
    trust_list_pub_key_t key;
    trust_list_footer_t footer;
    uint16_t i;

    if (!src->ready) {
        return TL_ERROR_GENERAL;
    }

    if (TL_OK != load_tl_header(src->storage.storage_type, &header) ||
        TL_OK != save_tl_header(dst->storage.storage_type, &header)) {
        dst->ready = false;
        return TL_ERROR_FLASH_WRITE;
    }

    for (i = 0; i < header.pub_keys_count; ++i) {
        if (TL_OK != load_tl_key(src->storage.storage_type, i, &key) ||
            TL_OK != save_tl_key(dst->storage.storage_type, &key)) {
            dst->ready = false;
            return TL_ERROR_FLASH_WRITE;
        }
    }

    if (TL_OK != load_tl_footer(src->storage.storage_type, &footer) ||
        TL_OK != save_tl_footer(dst->storage.storage_type, &footer)) {
        dst->ready = false;
        return TL_ERROR_FLASH_WRITE;
    }

    dst->ready = true;
    dst->keys_qty.keys_amount = src->keys_qty.keys_amount;
    dst->keys_qty.keys_count = src->keys_qty.keys_count;

    return TL_OK;
}

/******************************************************************************/
bool
verify_hl_key_sign(const uint8_t *key_to_check, size_t key_size) {

    //    size_t read_sz;
    //
    //    if (!key_to_check || sizeof(crypto_signed_hl_public_key_t) != key_size) {
    //        return false;
    //    }
    //
    //    crypto_signed_hl_public_key_t *key = (crypto_signed_hl_public_key_t *)key_to_check;
    //    crypto_signed_hl_public_key_t rec_key;
    //
    //    uint8_t buf[32];
    //    vsc_buffer_t hash;
    //    vsc_buffer_init(&hash);
    //    vsc_buffer_use(&hash, buf, sizeof(buf));
    //
    //    vscf_sha256_hash(vsc_data(key->public_key.val, PUBKEY_TINY_SZ), &hash);
    //
    //    for (size_t i = 0; i < PROVISION_KEYS_QTY; ++i) {
    //        vs_secbox_element_info_t el = {VS_SECBOX_ELEMENT_PBR, i};
    //
    //        if (GATEWAY_OK == vs_secbox_load(&el, (uint8_t *)&rec_key, sizeof(crypto_signed_hl_public_key_t),
    //        &read_sz) &&
    //            key->sign.signer_id.key_id == rec_key.public_key.id.key_id &&
    //            _verify_hash(&hash, vscf_alg_id_SHA256, rec_key.public_key.val, key->sign.val)) {
    //            return true;
    //        }
    //    }
    return false;
}

/******************************************************************************/
void
init_tl_storage() {

    _init_tl_ctx(TL_STORAGE_TYPE_DYNAMIC, &_tl_dynamic_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_STATIC, &_tl_static_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_TMP, &_tl_tmp_ctx);

    if (!_verify_tl(&_tl_dynamic_ctx) && _verify_tl(&_tl_static_ctx)) {
        if (TL_OK == _copy_tl_file(&_tl_dynamic_ctx, &_tl_static_ctx)) {
            _verify_tl(&_tl_dynamic_ctx);
        }
    }
}
/******************************************************************************/
int
save_tl_header(size_t storage_type, const trust_list_header_t *header) {

    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (!header || NULL == tl_ctx) {
        return TL_ERROR_PARAMS;
    }

    uint32_t tl_size = header->pub_keys_count * sizeof(trust_list_pub_key_t) + sizeof(trust_list_header_t) +
                       sizeof(trust_list_footer_t);

    if (header->tl_size > TL_STORAGE_SIZE || header->tl_size != tl_size) {
        return TL_ERROR_SMALL_BUFFER;
    }

    tl_ctx->ready = false;
    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = header->pub_keys_count;


    if (write_tl_header_file_impl(tl_ctx, header)) {
        return TL_OK;
    }

    return TL_ERROR_FLASH_WRITE;
}

/******************************************************************************/
int
load_tl_header(size_t storage_type, trust_list_header_t *header) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return TL_ERROR_PARAMS;
    }

    if (!tl_ctx->ready) {
        return TL_ERROR_GENERAL;
    }

    if (read_tl_header_file_impl(tl_ctx, header)) {
        return TL_OK;
    }

    return TL_ERROR_FLASH_READ;
}

/******************************************************************************/
int
save_tl_footer(size_t storage_type, const trust_list_footer_t *footer) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx || tl_ctx->keys_qty.keys_amount != tl_ctx->keys_qty.keys_count) {
        return TL_ERROR_PARAMS;
    }

    if (write_tl_footer_file_impl(tl_ctx, footer)) {
        return TL_OK;
    }

    return TL_ERROR_FLASH_WRITE;
}

/******************************************************************************/
int
load_tl_footer(size_t storage_type, trust_list_footer_t *footer) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return TL_ERROR_PARAMS;
    }

    if (!tl_ctx->ready) {
        return TL_ERROR_GENERAL;
    }

    if (read_tl_footer_file_impl(tl_ctx, footer)) {
        return TL_OK;
    }
    return TL_ERROR_FLASH_READ;
}

/******************************************************************************/
int
save_tl_key(size_t storage_type, const trust_list_pub_key_t *key) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return TL_ERROR_PARAMS;
    }

    if (tl_ctx->keys_qty.keys_count >= tl_ctx->keys_qty.keys_amount) {
        tl_ctx->keys_qty.keys_count = tl_ctx->keys_qty.keys_amount;
        return TL_ERROR_FLASH_WRITE;
    }

    if (!write_tl_key_file_impl(tl_ctx, tl_ctx->keys_qty.keys_count, key)) {
        return TL_ERROR_FLASH_WRITE;
    }

    tl_ctx->keys_qty.keys_count++;
    return TL_OK;
}

/******************************************************************************/
int
load_tl_key(size_t storage_type, tl_key_handle handle, trust_list_pub_key_t *key) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return TL_ERROR_PARAMS;
    }

    if (!tl_ctx->ready) {
        return TL_ERROR_GENERAL;
    }

    if (read_tl_key_file_impl(tl_ctx, handle, key)) {
        return TL_OK;
    }

    return TL_ERROR_FLASH_READ;
}

/******************************************************************************/
int
invalidate_tl(size_t storage_type) {
    trust_list_header_t header;
    size_t i;

    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return TL_ERROR_PARAMS;
    }

    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = 0;

    if (TL_OK != load_tl_header(storage_type, &header) || !remove_tl_header_file_impl(tl_ctx)) {
        return TL_OK;
    }

    tl_ctx->ready = false;

    if (!remove_tl_footer_file_impl(tl_ctx)) {
        return TL_OK;
    }

    for (i = 0; i < header.pub_keys_count; ++i) {
        if (!remove_tl_key_file_impl(tl_ctx, i)) {
            return TL_OK;
        }
    }

    return TL_OK;
}

/******************************************************************************/
int
apply_tmp_tl_to(size_t storage_type) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return TL_ERROR_PARAMS;
    }

    if (_verify_tl(&_tl_tmp_ctx)) {
        if (TL_OK != invalidate_tl(storage_type)) {
            return TL_ERROR_GENERAL;
        }

        return _copy_tl_file(tl_ctx, &_tl_tmp_ctx);
    }

    return TL_ERROR_GENERAL;
}
