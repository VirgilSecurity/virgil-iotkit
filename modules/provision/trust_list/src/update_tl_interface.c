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

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/update/update.h>
#include <endian-config.h>

static vs_update_interface_t _tl_update_ctx = {.storage_context = NULL};

/*************************************************************************/
static vs_status_e
_tl_get_header_size(void *context, vs_update_file_type_t *file_type, uint32_t *header_size) {
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(header_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *header_size = sizeof(vs_tl_header_t);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_get_data(void *context,
             vs_update_file_type_t *file_type,
             const void *file_header,
             void *data_buffer,
             uint32_t buffer_size,
             uint32_t *data_size,
             uint32_t data_offset) {
    vs_tl_element_info_t elem_info;
    vs_status_e ret_code;
    uint16_t out_size = *data_size;
    (void)file_header;
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(data_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buffer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *data_size = 0;
    elem_info.id = VS_TL_ELEMENT_TLC;
    elem_info.index = data_offset;

    STATUS_CHECK_RET(vs_tl_load_part(&elem_info, data_buffer, buffer_size, &out_size),
                     "Unable to get data (key %d)",
                     data_offset);
    *data_size = out_size;
    CHECK_RET(buffer_size >= *data_size,
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "Buffer size %d bytes is not enough to store data %d bytes size",
              buffer_size,
              *data_size);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_get_footer(void *context,
               vs_update_file_type_t *file_type,
               const void *file_header,
               void *footer_buffer,
               uint32_t buffer_size,
               uint32_t *footer_size) {
    vs_tl_element_info_t elem_info;
    vs_status_e ret_code;
    uint16_t out_size = *footer_size;
    (void)file_header;
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(footer_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buffer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_ASSERT(*footer_size < UINT16_MAX);
    CHECK_NOT_ZERO_RET(*footer_size < UINT16_MAX, VS_CODE_ERR_INCORRECT_ARGUMENT);

    *footer_size = 0;
    elem_info.id = VS_TL_ELEMENT_TLF;
    STATUS_CHECK_RET(vs_tl_load_part(&elem_info, footer_buffer, buffer_size, &out_size), "Unable to get footer");
    *footer_size = out_size;
    CHECK_RET(buffer_size >= *footer_size,
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "Buffer size %d bytes is not enough to store footer %d bytes size",
              buffer_size,
              *footer_size);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_set_header(void *context,
               vs_update_file_type_t *file_type,
               const void *file_header,
               uint32_t header_size,
               uint32_t *file_size) {
    vs_tl_element_info_t elem_info;
    const vs_tl_header_t *tl_header = file_header;
    vs_status_e ret_code;
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(header_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_ASSERT(*file_size < UINT16_MAX);
    CHECK_NOT_ZERO_RET(*file_size < UINT16_MAX, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *file_size = 0;

    elem_info.id = VS_TL_ELEMENT_TLH;
    STATUS_CHECK_RET(vs_tl_save_part(&elem_info, file_header, header_size), "Unable to set header");

    *file_size = VS_IOT_NTOHS(tl_header->pub_keys_count);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_set_data(void *context,
             vs_update_file_type_t *file_type,
             const void *file_header,
             const void *file_data,
             uint32_t data_size,
             uint32_t data_offset) {
    vs_tl_element_info_t elem_info;
    vs_status_e ret_code;
    (void)file_header;
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(file_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_ASSERT(data_size < UINT16_MAX);
    CHECK_NOT_ZERO_RET(data_size < UINT16_MAX, VS_CODE_ERR_NULLPTR_ARGUMENT);

    elem_info.id = VS_TL_ELEMENT_TLC;
    elem_info.index = data_offset;
    STATUS_CHECK_RET(vs_tl_save_part(&elem_info, file_data, data_size), "Unable to set data (key %d)", data_offset);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_set_footer(void *context,
               vs_update_file_type_t *file_type,
               const void *file_header,
               const void *file_footer,
               uint32_t footer_size) {
    vs_tl_element_info_t elem_info;
    vs_status_e ret_code;
    (void)file_header;
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(file_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_ASSERT(footer_size < UINT16_MAX);
    CHECK_NOT_ZERO_RET(footer_size < UINT16_MAX, VS_CODE_ERR_NULLPTR_ARGUMENT);

    elem_info.id = VS_TL_ELEMENT_TLF;
    STATUS_CHECK_RET(vs_tl_save_part(&elem_info, file_footer, footer_size), "Unable to set footer");

    return VS_CODE_OK;
}

/*************************************************************************/
static void
_tl_delete_object(void *context, vs_update_file_type_t *file_type) {
    (void)context;
    (void)file_type;
}

/*************************************************************************/
static vs_status_e
_tl_verify_object(void *context, vs_update_file_type_t *file_type) {
    (void)context;
    (void)file_type;
    vs_tl_element_info_t elem_info;
    uint16_t out_size;
    uint8_t data_buffer[sizeof(vs_tl_header_t)];
    (void)context;
    (void)file_type;

    elem_info.id = VS_TL_ELEMENT_TLH;
    elem_info.index = 0;

    return vs_tl_load_part(&elem_info, data_buffer, sizeof(data_buffer), &out_size);
}

/*************************************************************************/
static void
_tl_free_item(void *context, vs_update_file_type_t *file_type) {
    (void)context;
    (void)file_type;
}

/*************************************************************************/
static vs_status_e
_tl_get_header(void *context,
               vs_update_file_type_t *file_type,
               void *header_buffer,
               uint32_t buffer_size,
               uint32_t *header_size) {
    vs_tl_element_info_t elem_info;
    vs_status_e ret_code;
    vs_tl_header_t *tl_header = (vs_tl_header_t *)header_buffer;
    uint16_t out_size = *header_size;
    vs_tl_header_t host_header;
    (void)context;

    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(header_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(header_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(buffer_size == sizeof(vs_tl_header_t),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Buffer sdize %d bytes is not enough to store vs_tl_header_t %d bytes length",
              buffer_size,
              sizeof(vs_tl_header_t));

    *header_size = 0;
    elem_info.id = VS_TL_ELEMENT_TLH;
    STATUS_CHECK_RET(vs_tl_load_part(&elem_info, header_buffer, buffer_size, &out_size), "Unable to get header");
    vs_tl_header_to_host(tl_header, &host_header);
    *header_size = out_size;

    VS_IOT_MEMCPY(&file_type->info.version, &host_header.version, sizeof(vs_file_version_t));

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_get_file_size(void *context, vs_update_file_type_t *file_type, const void *file_header, uint32_t *file_size) {
    const vs_tl_header_t *tl_header = file_header;
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *file_size = VS_IOT_NTOHS(tl_header->pub_keys_count);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_get_version(vs_update_file_type_t *file_type, vs_file_version_t *file_version) {
    vs_tl_header_t tl_header;
    uint32_t header_size = sizeof(tl_header);
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(file_version, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(_tl_get_header(NULL, file_type, &tl_header, header_size, &header_size),
                     "Unable to get Trust List header");
    VS_IOT_ASSERT(header_size == sizeof(tl_header));

    VS_IOT_MEMCPY(file_version, &tl_header.version, sizeof(*file_version));

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_has_footer(void *context, vs_update_file_type_t *file_type, bool *has_footer) {
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(has_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *has_footer = true;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_tl_inc_data_offset(void *context,
                    vs_update_file_type_t *file_type,
                    uint32_t current_offset,
                    uint32_t loaded_data_size,
                    uint32_t *next_offset) {
    (void)context;
    (void)file_type;
    (void)next_offset;
    (void)loaded_data_size;

    CHECK_NOT_ZERO_RET(next_offset, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(current_offset < UINT32_MAX, VS_CODE_ERR_INCORRECT_ARGUMENT, "Next offset is outside of file");

    *next_offset = current_offset + 1;

    return VS_CODE_OK;
}

/*************************************************************************/
vs_status_e
vs_update_trust_list_init(vs_storage_op_ctx_t *storage_ctx) {

    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.close, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.deinit, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.del, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.load, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.open, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.save, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.sync, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_MEMSET(&_tl_update_ctx, 0, sizeof(_tl_update_ctx));

    _tl_update_ctx.get_header_size = _tl_get_header_size;
    _tl_update_ctx.get_file_size = _tl_get_file_size;
    _tl_update_ctx.has_footer = _tl_has_footer;
    _tl_update_ctx.inc_data_offset = _tl_inc_data_offset;
    _tl_update_ctx.get_header = _tl_get_header;
    _tl_update_ctx.get_data = _tl_get_data;
    _tl_update_ctx.get_footer = _tl_get_footer;
    _tl_update_ctx.set_header = _tl_set_header;
    _tl_update_ctx.set_data = _tl_set_data;
    _tl_update_ctx.set_footer = _tl_set_footer;
    _tl_update_ctx.verify_object = _tl_verify_object;
    _tl_update_ctx.delete_object = _tl_delete_object;
    _tl_update_ctx.free_item = _tl_free_item;
    _tl_update_ctx.storage_context = storage_ctx;

    return VS_CODE_OK;
}

/*************************************************************************/
vs_update_interface_t *
vs_tl_update_ctx(void) {
    return &_tl_update_ctx;
}

/*************************************************************************/
const vs_update_file_type_t *
vs_tl_update_file_type(void) {
    static vs_update_file_type_t file_type;
    static bool ready = false;

    if (!ready) {
        VS_IOT_MEMSET(&file_type, 0, sizeof(file_type));
        file_type.type = VS_UPDATE_TRUST_LIST;
        _tl_get_version(&file_type, &file_type.info.version);
        ready = true;
    }
    return &file_type;
}

/*************************************************************************/
