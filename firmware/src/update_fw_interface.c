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

#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/firmware/update_fw_interface.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/update/update.h>

/*************************************************************************/
static char *
_fw_update_describe_type(void *context, vs_update_file_type_t *file_type, char *buffer, size_t buf_size){
    const vs_firmware_info_t *fw_add_info = (const vs_firmware_info_t *) file_type->add_info;
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO(buffer);
    CHECK_NOT_ZERO(buf_size);

    VS_IOT_SNPRINTF(buffer, buf_size, "Firmware (manufacturer = \"%s\", device = \"%c%c%c%c\")", fw_add_info->manufacture_id,
            (char)fw_add_info->device_type[0], (char)fw_add_info->device_type[1], (char)fw_add_info->device_type[2], (char)fw_add_info->device_type[3]);

    return buffer;

    terminate:

    return NULL;
}

/*************************************************************************/
static char *
_fw_update_describe_version(void *context, vs_update_file_type_t *file_type, const vs_update_file_version_t *version, char *buffer, size_t buf_size, bool add_filetype_description){
    static const uint32_t START_EPOCH = 1420070400; // January 1, 2015 UTC
    char *output = buffer;
    size_t string_space = buf_size;
    size_t type_descr_size;
    static const size_t TYPE_DESCR_POSTFIX = 2;
    const vs_firmware_version_t *fw_ver = (const vs_firmware_version_t *) version;
    (void) context;

    CHECK_NOT_ZERO(file_type);
    CHECK_NOT_ZERO(version);
    CHECK_NOT_ZERO(buffer);
    CHECK_NOT_ZERO(buf_size);

    if(add_filetype_description){
        type_descr_size = VS_IOT_STRLEN(_fw_update_describe_type(context, file_type, buffer, buf_size));
        string_space -= type_descr_size;
        output += type_descr_size;
        if(string_space > TYPE_DESCR_POSTFIX){
            VS_IOT_STRCPY(output, ", ");
            string_space -= TYPE_DESCR_POSTFIX;
            output += TYPE_DESCR_POSTFIX;
        }
    }

    vs_firmware_describe_version(fw_ver, output, string_space);

    return buffer;

    terminate:

    return NULL;
}

/*************************************************************************/
static vs_status_code_e
_fw_update_get_header(void *context, vs_update_file_type_t *file_type, void *header_buffer, size_t buffer_size, size_t *header_size){
    vs_storage_op_ctx_t *ctx = context;
    vs_firmware_descriptor_t *fw_descr = header_buffer;
    const uint8_t *manufacture_id = file_type->add_info;
    const uint8_t *device_type = file_type->add_info + MANUFACTURE_ID_SIZE;
    vs_status_code_e ret_code;
    (void) file_type;

    CHECK_NOT_ZERO_RET(header_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(header_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(buffer_size >= sizeof(vs_firmware_descriptor_t), VS_CODE_ERR_NO_MEMORY, "Buffer size %d is lower that sizeof(vs_firmware_descriptor_t) = %d", buffer_size, sizeof(vs_firmware_descriptor_t));

    STATUS_CHECK_RET(vs_firmware_load_firmware_descriptor(ctx, manufacture_id, device_type, fw_descr), "Unable to load Firmware's header");
    *header_size = sizeof(vs_firmware_descriptor_t);
    CHECK_RET(buffer_size >= *header_size, VS_CODE_ERR_TOO_SMALL_BUFFER, "Buffer size %d bytes is not enough to store header %d bytes size", buffer_size, *header_size);

    VS_IOT_MEMCPY(file_type->add_info, &fw_descr->info, sizeof(fw_descr->info)); //-V512 (PVS_IGNORE)

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_fw_update_get_data(void *context, vs_update_file_type_t *file_type, const void *file_header, void *data_buffer, size_t buffer_size, size_t *data_size, size_t data_offset){
    vs_storage_op_ctx_t *ctx = context;
    const vs_firmware_descriptor_t *descriptor = file_header;
    vs_status_code_e ret_code;
    (void) file_type;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buffer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(buffer_size <= UINT16_MAX, VS_CODE_ERR_UINT16_T, "Buffer size %d is bigger than uint16_t %d", buffer_size, VS_CODE_ERR_UINT16_T);
    CHECK_RET(data_offset <= UINT32_MAX, VS_CODE_ERR_UINT32_T, "Data offset %d is bigger than uint16_t %d", data_offset, VS_CODE_ERR_UINT32_T);

    ret_code = vs_firmware_load_firmware_chunk(ctx, descriptor, data_offset, data_buffer, buffer_size, data_size);
    CHECK_RET(buffer_size >= *data_size, VS_CODE_ERR_TOO_SMALL_BUFFER, "Buffer size %d bytes is not enough to store data %d bytes size", buffer_size, *data_size);

    return ret_code;

}

/*************************************************************************/
static vs_status_code_e
_fw_update_get_footer(void *context, vs_update_file_type_t *file_type, const void *file_header, void *footer_buffer, size_t buffer_size, size_t *footer_size){
    vs_storage_op_ctx_t *ctx = context;
    const vs_firmware_descriptor_t *descriptor = file_header;
    vs_status_code_e ret_code;
    (void) file_type;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buffer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(buffer_size <= UINT16_MAX, VS_CODE_ERR_UINT16_T, "Buffer size %d is bigger than uint16_t %d", buffer_size, VS_CODE_ERR_UINT16_T);

    ret_code = vs_firmware_load_firmware_footer(ctx, descriptor, footer_buffer, buffer_size, footer_size);
    CHECK_RET(buffer_size >= *footer_size, VS_CODE_ERR_TOO_SMALL_BUFFER, "Buffer size %d bytes is not enough to store footer %d bytes size", buffer_size, *footer_size);

    return ret_code;
}

/*************************************************************************/
static vs_status_code_e
_fw_update_set_header(void *context, vs_update_file_type_t *file_type, const void *file_header, size_t header_size, size_t *file_size){
    vs_storage_op_ctx_t *ctx = context;
    const vs_firmware_descriptor_t *descriptor = file_header;
    (void) file_type;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(header_size == sizeof(*descriptor), VS_CODE_ERR_INCORRECT_ARGUMENT, "Incorrect header size %d byte while it must store vs_firmware_descriptor_t %d bytes length", header_size, sizeof(*descriptor));

    *file_size = descriptor->firmware_length;
    return vs_firmware_save_firmware_descriptor(ctx, descriptor);
}

/*************************************************************************/
static vs_status_code_e
_fw_update_set_data(void *context, vs_update_file_type_t *file_type, const void *file_header, const void *file_data, size_t data_size, size_t data_offset){
    vs_storage_op_ctx_t *ctx = context;
    const vs_firmware_descriptor_t *descriptor = file_header;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return vs_firmware_save_firmware_chunk(ctx, descriptor, file_data, data_size, data_offset);
}

/*************************************************************************/
static vs_status_code_e
_fw_update_set_footer(void *context, vs_update_file_type_t *file_type, const void *file_header, const void *file_footer, size_t footer_size){
    vs_storage_op_ctx_t *ctx = context;
    const vs_firmware_descriptor_t *fw_descr = file_header;
    vs_status_code_e res;
    (void) file_type;

    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(VS_CODE_OK == (res = vs_firmware_save_firmware_footer(ctx, fw_descr, file_footer)), res,
              "Unable to save footer");

    if(VS_CODE_OK != vs_firmware_verify_firmware(ctx, fw_descr)){
        VS_LOG_WARNING("Error while verifying firmware");

        if (VS_CODE_OK != (res = vs_firmware_delete_firmware(ctx, fw_descr))) {
            VS_LOG_ERROR("Unable to delete firmware");
            return res;
        }

        return VS_CODE_ERR_VERIFY;

    } else {
        res = vs_firmware_install_firmware(ctx, fw_descr);
    }

    return res;
}

/*************************************************************************/
static bool
_fw_update_file_is_newer(void *context, vs_update_file_type_t *file_type, const vs_update_file_version_t *available_file, const vs_update_file_version_t *new_file){
    const vs_firmware_version_t *fw_ver_available = (const vs_firmware_version_t *) available_file;
    const vs_firmware_version_t *fw_ver_new = (const vs_firmware_version_t *) new_file;
    (void) context;
    (void) file_type;

    VS_IOT_ASSERT(available_file);
    VS_IOT_ASSERT(new_file);

    if(!fw_ver_available->timestamp || !fw_ver_available->dev_build){
        return true;
    }

    if(fw_ver_new->dev_build > fw_ver_available->dev_build){
        return true;
    }

    return fw_ver_new->major > fw_ver_available->major || fw_ver_new->minor > fw_ver_available->minor;
}

/*************************************************************************/
static void
_fw_update_free_item(void *context, vs_update_file_type_t *file_type){
    (void) context;
    (void) file_type;
}

/*************************************************************************/
static vs_status_code_e
_fw_update_get_version(void *context, vs_update_file_type_t *file_type, vs_update_file_version_t *file_version){
    (void) context;

    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_NULLPTR_ARGUMENT);

    const vs_firmware_descriptor_t *fw_descriptor = (const vs_firmware_descriptor_t *) file_type->add_info;

    CHECK_NOT_ZERO_RET(file_version, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_MEMSET(file_version->version, 0, sizeof(file_version->version));
    VS_IOT_MEMCPY(file_version->version, &fw_descriptor->info.version, sizeof(fw_descriptor->info.version));

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_fw_update_get_header_size(void *context, vs_update_file_type_t *file_type, size_t *header_size){
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO_RET(header_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *header_size = sizeof(vs_firmware_descriptor_t);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_fw_update_get_file_size(void *context, vs_update_file_type_t *file_type, const void *file_header, size_t *file_size){
    const vs_firmware_descriptor_t *fw_header = file_header;
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *file_size = fw_header->firmware_length;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_fw_update_has_footer(void *context, vs_update_file_type_t *file_type, bool *has_footer){
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO_RET(has_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *has_footer = true;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_fw_update_inc_data_offset(void *context, vs_update_file_type_t *file_type, size_t current_offset, size_t loaded_data_size, size_t *next_offset){
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO_RET(next_offset, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *next_offset = current_offset + loaded_data_size;

    return VS_CODE_OK;
}

/*************************************************************************/
static bool
_fw_equal_file_type(void *context, vs_update_file_type_t *file_type, const vs_update_file_type_t *unknown_file_type){
    (void) context;
    CHECK_NOT_ZERO(file_type);
    CHECK_NOT_ZERO(unknown_file_type);

    if(unknown_file_type->file_type_id != VS_UPDATE_FIRMWARE) {
        return false;
    }

    const vs_firmware_info_t *first_file_add_info = (const vs_firmware_info_t *) file_type->add_info;
    const vs_firmware_info_t *second_file_add_info = (const vs_firmware_info_t *) unknown_file_type->add_info;

    return !VS_IOT_MEMCMP(first_file_add_info->manufacture_id, second_file_add_info->manufacture_id, sizeof(second_file_add_info->manufacture_id)) &&
           !VS_IOT_MEMCMP(first_file_add_info->device_type, second_file_add_info->device_type, sizeof(second_file_add_info->device_type));

    terminate:

    return false;
}

/*************************************************************************/
vs_status_code_e
vs_update_firmware_init(vs_update_interface_t *update_ctx, vs_storage_op_ctx_t *storage_ctx){

    CHECK_NOT_ZERO_RET(update_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.close, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.deinit, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.del, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.load, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.open, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.save, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl.size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_MEMSET(update_ctx, 0, sizeof(*update_ctx));

    update_ctx->get_version = _fw_update_get_version;
    update_ctx->get_header_size = _fw_update_get_header_size;
    update_ctx->get_file_size = _fw_update_get_file_size;
    update_ctx->has_footer = _fw_update_has_footer;
    update_ctx->inc_data_offset = _fw_update_inc_data_offset;
    update_ctx->equal_file_type = _fw_equal_file_type;
    update_ctx->get_header = _fw_update_get_header;
    update_ctx->get_data = _fw_update_get_data;
    update_ctx->get_footer = _fw_update_get_footer;
    update_ctx->set_header = _fw_update_set_header;
    update_ctx->set_data = _fw_update_set_data;
    update_ctx->set_footer = _fw_update_set_footer;
    update_ctx->file_is_newer = _fw_update_file_is_newer;
    update_ctx->free_item = _fw_update_free_item;
    update_ctx->describe_type = _fw_update_describe_type;
    update_ctx->describe_version = _fw_update_describe_version;
    update_ctx->file_context = storage_ctx;

    return VS_CODE_OK;
}