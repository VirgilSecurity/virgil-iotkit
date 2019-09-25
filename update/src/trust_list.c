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

#include <stdint.h>
#include <stddef.h>

#include <update-config.h>

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/update/firmware_hal.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/hsm/hsm_sw_sha2_routines.h>
#include <virgil/iot/update/trust_list.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>

/*************************************************************************/
static uint16_t
_tl_ver(const vs_update_file_version_t *version){
    return (uint16_t) version;
}

/*************************************************************************/
static char *
_tl_describe_type(void *context, const vs_update_file_type_t *file_type, char *buffer, size_t buf_size){
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO(buffer);
    CHECK_NOT_ZERO(buf_size);

    VS_IOT_SNPRINTF(buffer, buf_size, "Trust List");

    return buffer;

    terminate:

    return NULL;
}

/*************************************************************************/
static char *
_tl_describe_version(void *context, const vs_update_file_type_t *file_type, const vs_update_file_version_t *version, char *buffer, size_t buf_size, bool add_filetype_description){
    char *output = buffer;
    size_t string_space = buf_size;
    (void) context;

    CHECK_NOT_ZERO(buffer);
    CHECK_NOT_ZERO(buf_size);

    if(add_filetype_description){
        string_space -= VS_IOT_STRLEN(_tl_describe_type(context, file_type, buffer, buf_size));
        output += string_space;
        if(string_space > 2){
            VS_IOT_STRCPY(output, ", ");
            string_space -= 2;
        }
    }

    VS_IOT_SNPRINTF(output, string_space, "version %d", _tl_ver(version));

    return buffer;

    terminate:

    return NULL;
}


/*************************************************************************/
static vs_status_code_e
_tl_get_header_size(void *context, const vs_update_file_type_t *file_type, size_t *header_size){
    (void) context;
    (void) file_type;

    *header_size = sizeof(vs_tl_header_t);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_tl_get_data(void *context, const vs_update_file_type_t *file_type, const void *file_header, void *data_buffer, size_t buffer_size, size_t *data_size, size_t data_offset){
    vs_tl_element_info_t elem_info;
    vs_status_code_e ret_code;
    uint16_t out_size = *data_size;
    (void) file_header;
    (void) context;
    (void) file_type;

    *data_size = 0;
    elem_info.id = VS_TL_ELEMENT_TLC;
    elem_info.index = data_offset;

    STATUS_CHECK_RET(vs_tl_load_part(&elem_info, data_buffer, buffer_size, &out_size), "Unable to get data (key %d)", data_offset);

    *data_size = out_size;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_tl_get_footer(void *context, const vs_update_file_type_t *file_type, const void *file_header, void *footer_buffer, size_t buffer_size, size_t *footer_size){
    vs_tl_element_info_t elem_info;
    vs_status_code_e ret_code;
    uint16_t out_size = *footer_size;
    (void) file_header;
    (void) context;
    (void) file_type;

    *footer_size = 0;
    elem_info.id = VS_TL_ELEMENT_TLF;
    STATUS_CHECK_RET(vs_tl_load_part(&elem_info, footer_buffer, buffer_size, &out_size), "Unable to get footer");

    *footer_size = out_size;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_tl_set_header(void *context, const vs_update_file_type_t *file_type, const void *file_header, size_t header_size, size_t *file_size){
    vs_tl_element_info_t elem_info;
    const vs_tl_header_t *tl_header = file_header;
    vs_status_code_e ret_code;
    (void) context;
    (void) file_type;

    VS_IOT_ASSERT(header_size < UINT16_MAX);

    *file_size = 0;

    elem_info.id = VS_TL_ELEMENT_TLH;
    STATUS_CHECK_RET(vs_tl_save_part(&elem_info, file_header, header_size), "Unable to set header");

    *file_size = tl_header->pub_keys_count;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_tl_set_data(void *context, const vs_update_file_type_t *file_type, const void *file_header, const void *file_data, size_t data_size, size_t data_offset){
    vs_tl_element_info_t elem_info;
    vs_status_code_e ret_code;
    (void) file_header;
    (void) context;
    (void) file_type;

    VS_IOT_ASSERT(data_size < UINT16_MAX);

    elem_info.id = VS_TL_ELEMENT_TLC;
    elem_info.index = data_offset;
    STATUS_CHECK_RET(vs_tl_save_part(&elem_info, file_data, data_size), "Unable to set data (key %d)", data_offset);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_tl_set_footer(void *context, const vs_update_file_type_t *file_type, const void *file_header, const void *file_footer, size_t footer_size){
    vs_tl_element_info_t elem_info;
    vs_status_code_e ret_code;
    (void) file_header;
    (void) context;
    (void) file_type;

    VS_IOT_ASSERT(footer_size < UINT16_MAX);

    elem_info.id = VS_TL_ELEMENT_TLF;
    STATUS_CHECK_RET(vs_tl_save_part(&elem_info, file_footer, footer_size), "Unable to set footer");

    return VS_CODE_OK;
}

/*************************************************************************/
static bool
_tl_file_is_newer(void *context, const vs_update_file_type_t *file_type, const vs_update_file_version_t *available_file, const vs_update_file_version_t *new_file){
    (void) context;
    (void) file_type;

    return _tl_ver(new_file) > _tl_ver(available_file);
}

/*************************************************************************/
static void
_tl_free(void *context, const vs_update_file_type_t *file_type){
    (void) context;
    (void) file_type;
}

/*************************************************************************/
static vs_status_code_e
_tl_get_header(void *context, const vs_update_file_type_t *file_type, void *header_buffer, size_t buffer_size, size_t *header_size){
    vs_tl_element_info_t elem_info;
    vs_status_code_e ret_code;
    uint16_t out_size = *header_size;
    (void) context;
    (void) file_type;

    *header_size = 0;
    elem_info.id = VS_TL_ELEMENT_TLH;
    STATUS_CHECK_RET(vs_tl_load_part(&elem_info, header_buffer, buffer_size, &out_size), "Unable to get header");

    *header_size = out_size;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_tl_get_version(void *context, const vs_update_file_type_t *file_type, vs_update_file_version_t *file_version){
    vs_tl_header_t tl_header;
    size_t header_size = sizeof(tl_header);
    vs_status_code_e ret_code;

    CHECK_NOT_ZERO_RET(file_version, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(_tl_get_header(context, file_type, &tl_header, header_size, &header_size), "Unable to get Truat List header");
    VS_IOT_ASSERT(header_size == sizeof(tl_header));

    VS_IOT_MEMSET(&file_version->version, 0, sizeof(file_version->version));
    VS_IOT_MEMCPY(&file_version->version, &tl_header.version, sizeof(tl_header.version));

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_tl_has_footer(void *context, const vs_update_file_type_t *file_type, bool *has_footer){
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO_RET(has_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *has_footer = true;

    return VS_CODE_OK;
}
/*************************************************************************/
vs_status_code_e
vs_update_trust_list_init(vs_update_interface_t *update_ctx, vs_storage_op_ctx_t *storage_ctx){

    CHECK_NOT_ZERO_RET(update_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.close, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.deinit, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.del, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.load, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.open, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.save, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    update_ctx->get_version = _tl_get_version;
    update_ctx->get_header_size = _tl_get_header_size;
    update_ctx->has_footer = _tl_has_footer;
    update_ctx->get_header = _tl_get_header;
    update_ctx->get_data = _tl_get_data;
    update_ctx->get_footer = _tl_get_footer;
    update_ctx->set_header = _tl_set_header;
    update_ctx->set_data = _tl_set_data;
    update_ctx->set_footer = _tl_set_footer;
    update_ctx->file_is_newer = _tl_file_is_newer;
    update_ctx->free = _tl_free;
    update_ctx->describe_type = _tl_describe_type;
    update_ctx->describe_version = _tl_describe_version;
    update_ctx->file_context = storage_ctx;

    return VS_CODE_OK;
}