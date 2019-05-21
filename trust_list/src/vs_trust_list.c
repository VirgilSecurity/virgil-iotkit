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
#include "vs_trust_list.h"
#include "secbox.h"

/******************************************************************************/
void
vs_tl_init_storage(){
    init_tl_storage();
}

/******************************************************************************/
int
vs_tl_save_part(vs_tl_element_info_t *element_info, const uint8_t *in_data, size_t data_sz) {
    if (NULL == element_info || NULL == in_data || element_info->id <= VS_TL_ELEMENT_MIN ||
        element_info->id >= VS_TL_ELEMENT_MAX) {
        return TL_ERROR_PARAMS;
    }

    int res = TL_ERROR_GENERAL;

    switch (element_info->id) {
    case VS_TL_ELEMENT_TLH:
        if (sizeof(trust_list_header_t) == data_sz) {
            res = save_tl_header(TL_STORAGE_TYPE_TMP, (trust_list_header_t *)in_data);
        }
        break;
    case VS_TL_ELEMENT_TLF:

        if (sizeof(trust_list_footer_t) == data_sz) {
            res = save_tl_footer(TL_STORAGE_TYPE_TMP, (trust_list_footer_t *)in_data);

            if (TL_OK == res) {
                res = apply_tmp_tl_to(TL_STORAGE_TYPE_STATIC);
                if (TL_OK == res) {
                    res = apply_tmp_tl_to(TL_STORAGE_TYPE_DYNAMIC);
                }
            }
        }
        invalidate_tl(TL_STORAGE_TYPE_TMP);
        break;
    case VS_TL_ELEMENT_TLC:
        if (sizeof(trust_list_pub_key_t) == data_sz) {
            res = save_tl_key(TL_STORAGE_TYPE_TMP, (trust_list_pub_key_t *)in_data);
        }
        break;
    default:
        break;
    }

    return res;
}

/******************************************************************************/
int
vs_tl_load_part(vs_tl_element_info_t *element_info, uint8_t *out_data, size_t buf_sz, size_t *out_sz) {
    if (NULL == element_info || NULL == out_data || NULL == out_sz || element_info->id <= VS_TL_ELEMENT_MIN ||
        element_info->id >= VS_TL_ELEMENT_MAX) {
        return TL_ERROR_PARAMS;
    }

    int res = TL_ERROR_GENERAL;

    switch (element_info->id) {
    case VS_TL_ELEMENT_TLH:

        if (buf_sz >= sizeof(trust_list_header_t)) {
            *out_sz = sizeof(trust_list_header_t);
            res = load_tl_header(TL_STORAGE_TYPE_STATIC, (trust_list_header_t *)out_data);
        }
        break;
    case VS_TL_ELEMENT_TLF:

        if (buf_sz >= sizeof(trust_list_footer_t)) {
            *out_sz = sizeof(trust_list_footer_t);
            res = load_tl_footer(TL_STORAGE_TYPE_STATIC, (trust_list_footer_t *)out_data);
        }
        break;
    case VS_TL_ELEMENT_TLC:

        if (buf_sz >= sizeof(trust_list_pub_key_t)) {
            *out_sz = sizeof(trust_list_pub_key_t);
            res = load_tl_key(TL_STORAGE_TYPE_STATIC, element_info->index, (trust_list_pub_key_t *)out_data);
        }
        break;
    default:
        break;
    }

    return res;
}
