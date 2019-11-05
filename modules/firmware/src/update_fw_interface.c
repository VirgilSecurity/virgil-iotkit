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

#include <endian-config.h>

#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/macros/macros.h>


static vs_update_interface_t _fw_update_ctx = {.storage_context = NULL};
static vs_device_manufacture_id_t _manufacture;
static vs_device_type_t _device_type;

/*************************************************************************/
static char *
_fw_update_describe_type(void *context, vs_update_file_type_t *file_type, char *buffer, uint32_t buf_size) {
    (void)context;

    CHECK_NOT_ZERO(buffer);
    CHECK_NOT_ZERO(buf_size);

    // TODO: Fix print of manufacture_id
    VS_IOT_SNPRINTF(buffer,
                    buf_size,
                    "Firmware (manufacturer = \"%s\", device = \"%c%c%c%c\")",
                    file_type->info.manufacture_id,
                    (char)file_type->info.device_type[0],
                    (char)file_type->info.device_type[1],
                    (char)file_type->info.device_type[2],
                    (char)file_type->info.device_type[3]);

    return buffer;

terminate:

    return NULL;
}

/*************************************************************************/
static char *
_fw_update_describe_version(void *context,
                            vs_update_file_type_t *file_type,
                            const vs_file_version_t *version,
                            char *buffer,
                            uint32_t buf_size,
                            bool add_filetype_description) {
    static const uint32_t START_EPOCH = 1420070400; // January 1, 2015 UTC
    char *output = buffer;
    uint32_t string_space = buf_size;
    uint32_t type_descr_size;
    static const uint32_t TYPE_DESCR_POSTFIX = 2;
    const vs_file_version_t *fw_ver = (const vs_file_version_t *)version;
    (void)context;

    CHECK_NOT_ZERO(file_type);
    CHECK_NOT_ZERO(version);
    CHECK_NOT_ZERO(buffer);
    CHECK_NOT_ZERO(buf_size);

    if (add_filetype_description) {
        type_descr_size = VS_IOT_STRLEN(_fw_update_describe_type(context, file_type, buffer, buf_size));
        string_space -= type_descr_size;
        output += type_descr_size;
        if (string_space > TYPE_DESCR_POSTFIX) {
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
static vs_status_e
_fw_update_get_header(void *context,
                      vs_update_file_type_t *file_type,
                      void *header_buffer,
                      uint32_t buffer_size,
                      uint32_t *header_size) {
    (void)context;
    vs_firmware_descriptor_t *fw_descr = header_buffer;

    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(header_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(header_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(buffer_size >= sizeof(vs_firmware_descriptor_t),
              VS_CODE_ERR_NO_MEMORY,
              "Buffer size %d is lower that sizeof(vs_firmware_descriptor_t) = %d",
              buffer_size,
              sizeof(vs_firmware_descriptor_t));

    if (VS_CODE_OK !=
        vs_firmware_load_firmware_descriptor(file_type->info.manufacture_id, file_type->info.device_type, fw_descr)) {
        VS_LOG_WARNING("Unable to load Firmware's header");
        VS_IOT_MEMSET(fw_descr, 0, sizeof(*fw_descr));
        VS_IOT_MEMCPY(
                &fw_descr->info.manufacture_id, file_type->info.manufacture_id, sizeof(fw_descr->info.manufacture_id));
        VS_IOT_MEMCPY(&fw_descr->info.device_type, file_type->info.device_type, sizeof(fw_descr->info.device_type));
    }

    *header_size = sizeof(vs_firmware_descriptor_t);
    CHECK_RET(buffer_size >= *header_size,
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "Buffer size %d bytes is not enough to store header %d bytes size",
              buffer_size,
              *header_size);

    VS_IOT_MEMCPY(&file_type->info, &fw_descr->info, sizeof(fw_descr->info));

    // Normalize byte order
    vs_firmware_hton_descriptor(fw_descr);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_fw_update_get_data(void *context,
                    vs_update_file_type_t *file_type,
                    const void *file_header,
                    void *data_buffer,
                    uint32_t buffer_size,
                    uint32_t *data_size,
                    uint32_t data_offset) {

    const vs_firmware_descriptor_t *descriptor = file_header;
    vs_status_e ret_code;
    (void)file_type;
    size_t chunk_size;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buffer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(buffer_size <= UINT16_MAX,
              VS_CODE_ERR_FORMAT_OVERFLOW,
              "Buffer size %d is bigger than uint16_t %d",
              buffer_size,
              VS_CODE_ERR_FORMAT_OVERFLOW);
    CHECK_RET(data_offset <= UINT32_MAX,
              VS_CODE_ERR_FORMAT_OVERFLOW,
              "Data offset %d is bigger than uint16_t %d",
              data_offset,
              VS_CODE_ERR_FORMAT_OVERFLOW);

    ret_code = vs_firmware_load_firmware_chunk(descriptor, data_offset, data_buffer, buffer_size, &chunk_size);
    CHECK_RET(buffer_size >= chunk_size,
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "Buffer size %d bytes is not enough to store data %d bytes size",
              buffer_size,
              chunk_size);

    *data_size = chunk_size;

    return ret_code;
}

/*************************************************************************/
static vs_status_e
_fw_update_get_footer(void *context,
                      vs_update_file_type_t *file_type,
                      const void *file_header,
                      void *footer_buffer,
                      uint32_t buffer_size,
                      uint32_t *footer_size) {
    const vs_firmware_descriptor_t *net_descr = file_header;
    vs_firmware_descriptor_t descriptor;
    vs_status_e ret_code;
    (void)file_type;
    size_t data_sz;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buffer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_MEMCPY(&descriptor, net_descr, sizeof(descriptor));

    // Normalize byte order
    vs_firmware_ntoh_descriptor(&descriptor);

    CHECK_RET(buffer_size <= UINT16_MAX,
              VS_CODE_ERR_FORMAT_OVERFLOW,
              "Buffer size %d is bigger than uint16_t %d",
              buffer_size,
              VS_CODE_ERR_FORMAT_OVERFLOW);

    ret_code = vs_firmware_load_firmware_footer(&descriptor, footer_buffer, buffer_size, &data_sz);
    CHECK_RET(buffer_size >= data_sz,
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "Buffer size %d bytes is not enough to store footer %d bytes size",
              buffer_size,
              data_sz);
    *footer_size = data_sz;

    return ret_code;
}

/*************************************************************************/
static vs_status_e
_fw_update_set_header(void *context,
                      vs_update_file_type_t *file_type,
                      const void *file_header,
                      uint32_t header_size,
                      uint32_t *file_size) {
    vs_firmware_descriptor_t *descriptor = (vs_firmware_descriptor_t *)file_header;
    (void)file_type;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Normalize byte order
    vs_firmware_ntoh_descriptor(descriptor);
    CHECK_RET(header_size == sizeof(*descriptor),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Incorrect header size %d byte while it must store vs_firmware_descriptor_t %d bytes length",
              header_size,
              sizeof(*descriptor));

    *file_size = descriptor->firmware_length;
    return vs_firmware_save_firmware_descriptor(descriptor);
}

/*************************************************************************/
static vs_status_e
_fw_update_set_data(void *context,
                    vs_update_file_type_t *file_type,
                    const void *file_header,
                    const void *file_data,
                    uint32_t data_size,
                    uint32_t data_offset) {
    const vs_firmware_descriptor_t *descriptor = file_header;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return vs_firmware_save_firmware_chunk(descriptor, file_data, data_size, data_offset);
}

/*************************************************************************/
static vs_status_e
_fw_update_set_footer(void *context,
                      vs_update_file_type_t *file_type,
                      const void *file_header,
                      const void *file_footer,
                      uint32_t footer_size) {
    vs_storage_op_ctx_t *ctx = context;
    const vs_firmware_descriptor_t *fw_descr = file_header;
    vs_status_e res;
    (void)file_type;

    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    res = vs_firmware_save_firmware_footer(fw_descr, file_footer);
    CHECK_RET(VS_CODE_OK == res, res, "Unable to save footer");

    if (VS_CODE_OK != vs_firmware_verify_firmware(fw_descr)) {
        VS_LOG_WARNING("Error while verifying firmware");

        if (VS_CODE_OK != (res = vs_firmware_delete_firmware(fw_descr))) {
            VS_LOG_ERROR("Unable to delete firmware");
            return res;
        }

        return VS_CODE_ERR_VERIFY;

    } else {
        res = vs_firmware_install_firmware(fw_descr);
    }

    return res;
}

/*************************************************************************/
static bool
_fw_update_file_is_newer(void *context,
                         vs_update_file_type_t *file_type,
                         const vs_file_version_t *available_file,
                         const vs_file_version_t *new_file) {
    const vs_file_version_t *fw_ver_available = (const vs_file_version_t *)available_file;
    const vs_file_version_t *fw_ver_new = (const vs_file_version_t *)new_file;
    (void)context;
    (void)file_type;

    VS_IOT_ASSERT(available_file);
    VS_IOT_ASSERT(new_file);

    // TODO: Fix it ! Use version comparision

    if (!fw_ver_available->timestamp || !fw_ver_available->build) {
        return true;
    }

    if (fw_ver_new->build > fw_ver_available->build) {
        return true;
    }

    return fw_ver_new->major > fw_ver_available->major || fw_ver_new->minor > fw_ver_available->minor;
}

/*************************************************************************/
static void
_fw_update_free_item(void *context, vs_update_file_type_t *file_type) {
    (void)context;
    (void)file_type;
}

/*************************************************************************/
static vs_status_e
_fw_update_get_header_size(void *context, vs_update_file_type_t *file_type, uint32_t *header_size) {
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(header_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *header_size = sizeof(vs_firmware_descriptor_t);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_fw_update_get_file_size(void *context,
                         vs_update_file_type_t *file_type,
                         const void *file_header,
                         uint32_t *file_size) {
    const vs_firmware_descriptor_t *fw_header = file_header;
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *file_size = fw_header->firmware_length;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_fw_update_has_footer(void *context, vs_update_file_type_t *file_type, bool *has_footer) {
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(has_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *has_footer = true;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_fw_update_inc_data_offset(void *context,
                           vs_update_file_type_t *file_type,
                           uint32_t current_offset,
                           uint32_t loaded_data_size,
                           uint32_t *next_offset) {
    (void)context;
    (void)file_type;

    CHECK_NOT_ZERO_RET(next_offset, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *next_offset = current_offset + loaded_data_size;

    return VS_CODE_OK;
}

/*************************************************************************/
vs_status_e
vs_update_firmware_init(vs_storage_op_ctx_t *storage_ctx,
                        vs_device_manufacture_id_t manufacture,
                        vs_device_type_t device_type) {

    CHECK_NOT_ZERO_RET(manufacture, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(device_type, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.close, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.deinit, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.del, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.load, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.open, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.save, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.sync, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_MEMSET(&_fw_update_ctx, 0, sizeof(_fw_update_ctx));

    _fw_update_ctx.get_header_size = _fw_update_get_header_size;
    _fw_update_ctx.get_file_size = _fw_update_get_file_size;
    _fw_update_ctx.has_footer = _fw_update_has_footer;
    _fw_update_ctx.inc_data_offset = _fw_update_inc_data_offset;
    _fw_update_ctx.get_header = _fw_update_get_header;
    _fw_update_ctx.get_data = _fw_update_get_data;
    _fw_update_ctx.get_footer = _fw_update_get_footer;
    _fw_update_ctx.set_header = _fw_update_set_header;
    _fw_update_ctx.set_data = _fw_update_set_data;
    _fw_update_ctx.set_footer = _fw_update_set_footer;
    _fw_update_ctx.file_is_newer = _fw_update_file_is_newer;
    _fw_update_ctx.free_item = _fw_update_free_item;
    _fw_update_ctx.describe_type = _fw_update_describe_type;
    _fw_update_ctx.describe_version = _fw_update_describe_version;
    _fw_update_ctx.storage_context = storage_ctx;

    VS_IOT_MEMCPY(_manufacture, manufacture, sizeof(_manufacture));
    VS_IOT_MEMCPY(_device_type, device_type, sizeof(_device_type));

    return VS_CODE_OK;
}

/*************************************************************************/
vs_update_interface_t *
vs_firmware_update_ctx(void) {
    return &_fw_update_ctx;
}

/*************************************************************************/
const vs_update_file_type_t *
vs_firmware_update_file_type(void) {
    static vs_update_file_type_t file_type;
    static bool ready = false;

    if (!ready) {
        VS_IOT_MEMSET(&file_type, 0, sizeof(file_type));
        file_type.type = VS_UPDATE_FIRMWARE;
        VS_IOT_MEMCPY(file_type.info.manufacture_id, _manufacture, sizeof(_manufacture));
        VS_IOT_MEMCPY(file_type.info.device_type, _device_type, sizeof(_device_type));
        ready = true;
    }
    return &file_type;
}

/*************************************************************************/
