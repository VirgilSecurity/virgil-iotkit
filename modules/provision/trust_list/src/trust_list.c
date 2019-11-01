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

#include "virgil/iot/trust_list/tl_structs.h"
#include "private/tl-private.h"
#include "virgil/iot/trust_list/trust_list.h"
#include <endian-config.h>

/******************************************************************************/
vs_status_e
vs_tl_init(vs_storage_op_ctx_t *op_ctx, vs_hsm_impl_t *hsm) {
    return vs_tl_storage_init_internal(op_ctx, hsm);
}

/******************************************************************************/
vs_status_e
vs_tl_deinit() {
    return vs_tl_storage_deinit_internal();
}

/******************************************************************************/
vs_status_e
vs_tl_save_part(vs_tl_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz) {
    if (NULL == element_info || NULL == in_data || element_info->id <= VS_TL_ELEMENT_MIN ||
        element_info->id >= VS_TL_ELEMENT_MAX) {
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    vs_status_e res = VS_CODE_ERR_FILE_WRITE;

    switch (element_info->id) {
    case VS_TL_ELEMENT_TLH:
        if (sizeof(vs_tl_header_t) == data_sz) {
            res = vs_tl_header_save(TL_STORAGE_TYPE_TMP, (vs_tl_header_t *)in_data);
        }
        break;
    case VS_TL_ELEMENT_TLF:

        res = vs_tl_footer_save(TL_STORAGE_TYPE_TMP, in_data, data_sz);

        if (VS_CODE_OK == res) {
            res = vs_tl_apply_tmp_to(TL_STORAGE_TYPE_DYNAMIC);
            if (VS_CODE_OK == res && VS_CODE_OK != vs_tl_verify_storage(TL_STORAGE_TYPE_STATIC)) {
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
vs_status_e
vs_tl_load_part(vs_tl_element_info_t *element_info, uint8_t *out_data, uint16_t buf_sz, uint16_t *out_sz) {
    if (NULL == element_info || NULL == out_data || NULL == out_sz || element_info->id <= VS_TL_ELEMENT_MIN ||
        element_info->id >= VS_TL_ELEMENT_MAX) {
        return VS_CODE_ERR_FILE_READ;
    }

    int res = VS_CODE_ERR_FILE_READ;

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

/******************************************************************************/
void
vs_tl_header_to_host(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data) {
    *dst_data = *src_data;
    dst_data->pub_keys_count = VS_IOT_NTOHS(src_data->pub_keys_count);
    dst_data->tl_size = VS_IOT_NTOHL(src_data->tl_size);
    dst_data->version.build = VS_IOT_NTOHL(src_data->version.build);
    dst_data->version.timestamp = VS_IOT_NTOHL(src_data->version.timestamp);
}

/******************************************************************************/
void
vs_tl_header_to_net(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data) {
    *dst_data = *src_data;
    dst_data->pub_keys_count = VS_IOT_HTONS(src_data->pub_keys_count);
    dst_data->tl_size = VS_IOT_HTONL(src_data->tl_size);
    dst_data->version.build = VS_IOT_HTONL(src_data->version.build);
    dst_data->version.timestamp = VS_IOT_HTONL(src_data->version.timestamp);
}