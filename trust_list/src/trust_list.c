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
#include <trust_list-config.h>
#include <logger-config.h>

#include "virgil/iot/trust_list/tl_structs.h"
#include "virgil/iot/trust_list/private/tl_operations.h"
#include "virgil/iot/trust_list/trust_list.h"

/******************************************************************************/
int
vs_tl_init(const vs_storage_op_ctx_t *op_ctx) {
    return vs_tl_storage_init_internal(op_ctx);
}

/******************************************************************************/
int
vs_tl_deinit() {
    return vs_tl_storage_deinit_internal();
}

/******************************************************************************/
int
vs_tl_save_part(vs_tl_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz) {
    if (NULL == element_info || NULL == in_data || element_info->id <= VS_TL_ELEMENT_MIN ||
        element_info->id >= VS_TL_ELEMENT_MAX) {
        return VS_STORAGE_ERROR_PARAMS;
    }

    int res = VS_STORAGE_ERROR_GENERAL;

    switch (element_info->id) {
    case VS_TL_ELEMENT_TLH:
        if (sizeof(vs_tl_header_t) == data_sz) {
            res = vs_tl_header_save(TL_STORAGE_TYPE_TMP, (vs_tl_header_t *)in_data);
        }
        break;
    case VS_TL_ELEMENT_TLF:

        res = vs_tl_footer_save(TL_STORAGE_TYPE_TMP, in_data, data_sz);

        if (VS_STORAGE_OK == res) {
            res = vs_tl_apply_tmp_to(TL_STORAGE_TYPE_DYNAMIC);
            if (VS_STORAGE_OK == res && VS_STORAGE_OK != vs_tl_verify_storage(TL_STORAGE_TYPE_STATIC)) {
                res = vs_tl_apply_tmp_to(TL_STORAGE_TYPE_STATIC);
            }
        }

        vs_tl_invalidate(TL_STORAGE_TYPE_TMP);
        break;
    case VS_TL_ELEMENT_TLC:
        res = vs_tl_key_save(TL_STORAGE_TYPE_TMP, in_data, data_sz);
        break;
    default:
        break;
    }

    return res;
}

/******************************************************************************/
int
vs_tl_load_part(vs_tl_element_info_t *element_info, uint8_t *out_data, uint16_t buf_sz, uint16_t *out_sz) {
    if (NULL == element_info || NULL == out_data || NULL == out_sz || element_info->id <= VS_TL_ELEMENT_MIN ||
        element_info->id >= VS_TL_ELEMENT_MAX) {
        return VS_STORAGE_ERROR_PARAMS;
    }

    int res = VS_STORAGE_ERROR_GENERAL;

    switch (element_info->id) {
    case VS_TL_ELEMENT_TLH:

        if (buf_sz >= sizeof(vs_tl_header_t)) {
            *out_sz = sizeof(vs_tl_header_t);
            res = vs_tl_header_load(TL_STORAGE_TYPE_DYNAMIC, (vs_tl_header_t *)out_data);
        }
        break;
    case VS_TL_ELEMENT_TLF:

        if (buf_sz >= sizeof(vs_tl_footer_t)) {
            *out_sz = sizeof(vs_tl_footer_t);
            res = vs_tl_footer_load(TL_STORAGE_TYPE_DYNAMIC, out_data, buf_sz, out_sz);
        }
        break;
    case VS_TL_ELEMENT_TLC:
        res = vs_tl_key_load(TL_STORAGE_TYPE_DYNAMIC, element_info->index, out_data, buf_sz, out_sz);
        break;
    default:
        break;
    }

    return res;
}
