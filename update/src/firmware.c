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
#include <virgil/iot/update/firmware.h>

static const vs_key_type_e sign_rules_list[VS_FW_SIGNATURES_QTY] = VS_FW_SIGNER_TYPE_LIST;

#define DESCRIPTORS_FILENAME "firmware_descriptors"
#define FILEDESCR_BUF_SZ    (80)

/*************************************************************************/
static char *
_fw_describe_type(void *context, const vs_update_file_type_t *file_type, char *buffer, size_t buf_size){
    const vs_update_fw_info_t *fw_add_info = (const vs_update_fw_info_t *) file_type->add_info;
    (void) context;

    CHECK_NOT_ZERO(file_type);
    CHECK_NOT_ZERO(buffer);
    CHECK_NOT_ZERO(buf_size);

    VS_IOT_SNPRINTF(buffer, buf_size, "Firmware (manufacturer = \"%s\", device = \"%s\")", fw_add_info->manufacture_id, fw_add_info->device_type);

    return buffer;

    terminate:

    return NULL;
}

/*************************************************************************/
static char *
_fw_describe_version(void *context, const vs_update_file_type_t *file_type, const vs_update_file_version_t *version, char *buffer, size_t buf_size, bool add_filetype_description){
    char *output = buffer;
    size_t string_space = buf_size;
    const vs_update_fw_version_t *fw_ver = (const vs_update_fw_version_t *) version;
    (void) context;

    CHECK_NOT_ZERO(file_type);
    CHECK_NOT_ZERO(version);
    CHECK_NOT_ZERO(buffer);
    CHECK_NOT_ZERO(buf_size);

    if(add_filetype_description){
        string_space -= VS_IOT_STRLEN(_fw_describe_type(context, file_type, buffer, buf_size));
        output += string_space;
        if(string_space > 2){
            VS_IOT_STRCPY(output, ", ");
            string_space -= 2;
        }
    }

    VS_IOT_SNPRINTF(output, string_space, "version %d.%d, build %d, patch %d, milestone %d, timestamp %lu",
                    fw_ver->major, fw_ver->minor, fw_ver->dev_build, fw_ver->patch, fw_ver->dev_milestone,
                    (long unsigned) fw_ver->timestamp);

    return buffer;

    terminate:

    return NULL;
}

/*************************************************************************/
static void
_create_data_filename(const uint8_t manufacture_id[MANUFACTURE_ID_SIZE],
                      const uint8_t device_type[DEVICE_TYPE_SIZE],
                      vs_storage_element_id_t id) {
    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    VS_IOT_MEMCPY(&id[0], manufacture_id, MANUFACTURE_ID_SIZE);
    VS_IOT_MEMCPY(&id[MANUFACTURE_ID_SIZE], device_type, DEVICE_TYPE_SIZE);
}

/*************************************************************************/
static void
_create_fw_descr_filename(vs_storage_element_id_t id) {
    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    VS_IOT_MEMCPY(&id[0], DESCRIPTORS_FILENAME, sizeof(DESCRIPTORS_FILENAME));
}

/*************************************************************************/
static vs_status_code_e
_read_data(const vs_storage_op_ctx_t *ctx,
           vs_storage_element_id_t id,
           uint32_t offset,
           uint8_t *data,
           size_t buff_sz,
           size_t *data_sz) {
    vs_storage_file_t f = NULL;
    int file_sz;

    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *data_sz = 0;
    file_sz = ctx->impl.size(ctx->storage_ctx, id);

    CHECK_RET(0 < file_sz, VS_CODE_ERR_FILE_READ, "Can't find file");
    CHECK_RET(file_sz >= offset + buff_sz, VS_CODE_ERR_FILE, "File format error");

    f = ctx->impl.open(ctx->storage_ctx, id);
    CHECK_RET(NULL != f, VS_CODE_ERR_FILE_READ, "Can't open file");

    if (VS_STORAGE_OK != ctx->impl.load(ctx->storage_ctx, f, offset, data, buff_sz)) {
        VS_LOG_ERROR("Can't load data from file");
        ctx->impl.close(ctx->storage_ctx, f);
        return VS_CODE_ERR_FILE_READ;
    }

    *data_sz = buff_sz;
    return ctx->impl.close(ctx->storage_ctx, f);
}

/******************************************************************************/
static vs_status_code_e
_write_data(const vs_storage_op_ctx_t *ctx,
            vs_storage_element_id_t id,
            uint32_t offset,
            const void *data,
            size_t data_sz) {
    vs_storage_file_t f = NULL;

    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(data_sz <= ctx->file_sz_limit, VS_CODE_ERR_INCORRECT_ARGUMENT, "Requested size is too big");

    f = ctx->impl.open(ctx->storage_ctx, id);
    if (NULL == f) {
        VS_LOG_ERROR("Can't open file");
        return VS_CODE_ERR_FILE_WRITE;
    }

    if (VS_STORAGE_OK != ctx->impl.save(ctx->storage_ctx, f, offset, data, data_sz)) {
        ctx->impl.close(ctx->storage_ctx, f);
        VS_LOG_ERROR("Can't save data to file");
        return VS_CODE_ERR_FILE_WRITE;
    }

    return ctx->impl.close(ctx->storage_ctx, f);
}

/******************************************************************************/
static bool
_is_rule_equal_to(vs_key_type_e type) {
    uint8_t i;
    for (i = 0; i < VS_FW_SIGNATURES_QTY; ++i) {
        if (sign_rules_list[i] == type) {
            return true;
        }
    }
    return false;
}

/*************************************************************************/
static vs_status_code_e
_fw_get_header(void *context, const vs_update_file_type_t *file_type, void *header_buffer, size_t buffer_size, size_t *header_size){
    vs_storage_op_ctx_t *ctx = (vs_storage_op_ctx_t *) context;
    const vs_update_fw_add_info_t *fw_add_info = (const vs_update_fw_add_info_t *)file_type->add_info;
    vs_update_fw_descriptor_t *fw_descr = header_buffer;
    vs_storage_element_id_t desc_id;
    int file_sz;
    uint8_t *buf = NULL;
    uint32_t offset = 0;
    vs_status_code_e ret_code = VS_CODE_OK;

    CHECK_NOT_ZERO_RET(context, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(header_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(buffer_size >= sizeof(*fw_descr), VS_CODE_ERR_TOO_SMALL_BUFFER, "Too small header's buffer %d bytes while %d bytes needed", (int)buffer_size, (int)sizeof(*fw_descr));

    // cppcheck-suppress uninitvar
    _create_fw_descr_filename(desc_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, desc_id);

    if (file_sz <= 0) {
        goto terminate;
    }

    size_t read_sz;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NO_MEMORY);

    if (VS_STORAGE_OK != _read_data(ctx, desc_id, 0, buf, file_sz, &read_sz)) {
        ret_code = VS_CODE_ERR_FILE_READ;
        goto terminate;
    }

    while (offset + sizeof(vs_update_fw_descriptor_t) <= file_sz) {
        vs_update_fw_descriptor_t *ptr = (vs_update_fw_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->info.manufacture_id, fw_add_info->manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->info.device_type, fw_add_info->device_type, DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMCPY(fw_descr, ptr, sizeof(*fw_descr));
            *header_size = sizeof(*fw_descr);
            ret_code = VS_CODE_OK;
            break;
        }

        offset += sizeof(vs_update_fw_descriptor_t);
    }

    terminate:
    VS_IOT_FREE(buf);

    return ret_code;

}

/*************************************************************************/
static vs_status_code_e
_fw_get_data(void *context, const vs_update_file_type_t *file_type, const void *file_header, void *data_buffer, size_t buffer_size, size_t *data_size, size_t data_offset){
    vs_storage_op_ctx_t *ctx = context;
    const vs_update_fw_descriptor_t *fw_descr = file_header;
    vs_storage_element_id_t data_id;
    (void) file_type;

    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_size, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_RET(data_offset < fw_descr->firmware_length, VS_CODE_ERR_INCORRECT_PARAMETER, "Data offset %lu is bigger than file size %lu", data_offset, fw_descr->firmware_length);

    // cppcheck-suppress uninitvar
    _create_data_filename(fw_descr->info.manufacture_id, fw_descr->info.device_type, data_id);

    return _read_data(ctx, data_id, data_offset, data_buffer, buffer_size, data_size);
}

/*************************************************************************/
static vs_status_code_e
_fw_get_footer(void *context, const vs_update_file_type_t *file_type, const void *file_header, void *footer_buffer, size_t buffer_size, size_t *footer_size){
    vs_storage_op_ctx_t *ctx = context;
    const vs_update_fw_descriptor_t *fw_descr = file_header;
    int file_sz;
    vs_storage_element_id_t data_id;
    (void) file_type;

    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_buffer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_size, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(buffer_size, VS_CODE_ERR_ZERO_ARGUMENT);

    *footer_size = 0;
    // cppcheck-suppress uninitvar
    _create_data_filename(fw_descr->info.manufacture_id, fw_descr->info.device_type, data_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, data_id);

    if (file_sz > 0) {

        int32_t footer_sz = file_sz - fw_descr->firmware_length;
        CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_CODE_ERR_INCORRECT_ARGUMENT, "Incorrect footer size");

        *footer_size = (uint16_t)footer_sz;
        CHECK_RET(footer_sz <= buffer_size, VS_CODE_ERR_INCORRECT_ARGUMENT, "Buffer to small");

        return _read_data(ctx, data_id, fw_descr->firmware_length, footer_buffer, footer_sz, footer_size);
    }

    return VS_CODE_ERR_FILE_READ;
}

/*************************************************************************/
static vs_status_code_e
_fw_set_header(void *context, const vs_update_file_type_t *file_type, const void *file_header, size_t header_size, size_t *file_size){
    vs_storage_op_ctx_t *ctx = context;
    const vs_update_fw_descriptor_t *fw_descr = file_header;
    int file_sz;
    vs_storage_element_id_t desc_id;
    uint8_t *buf = NULL;
    uint8_t *newbuf = NULL;
    uint32_t offset = 0;
    int res;
    (void) file_type;

    CHECK_NOT_ZERO_RET(fw_descr, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(header_size == sizeof(*fw_descr), VS_CODE_ERR_TOO_SMALL_BUFFER, "sizeof(vs_update_fw_descriptor_t) = %d whereas header_sz = %d", (int)sizeof(*fw_descr), (int)header_size);

    *file_size = 0;

    // cppcheck-suppress uninitvar
    _create_fw_descr_filename(desc_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, desc_id);

    if (file_sz > 0) {
        uint16_t read_sz;
        buf = VS_IOT_CALLOC(1, file_sz);
        CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NO_MEMORY);

        if (VS_STORAGE_OK != _read_data(ctx, desc_id, 0, buf, file_sz, &read_sz)) {
            VS_IOT_FREE(buf);
            return VS_CODE_ERR_FILE_READ;
        }

        while (offset < file_sz) {
            if (offset + sizeof(vs_update_fw_descriptor_t) > file_sz) {
                file_sz = offset;
                break;
            }

            vs_update_fw_descriptor_t *ptr = (vs_update_fw_descriptor_t *)(buf + offset);

            if (0 == memcmp(ptr->info.manufacture_id, fw_descr->info.manufacture_id, MANUFACTURE_ID_SIZE) &&
                0 == memcmp(ptr->info.device_type, fw_descr->info.device_type, DEVICE_TYPE_SIZE)) {
                VS_IOT_MEMCPY(ptr, fw_descr, sizeof(vs_update_fw_descriptor_t));
                newbuf = buf;
                goto save_data;
            }

            offset += sizeof(vs_update_fw_descriptor_t);
        }

        newbuf = VS_IOT_CALLOC(1, file_sz + sizeof(vs_update_fw_descriptor_t));

        if (NULL == newbuf) {
            VS_IOT_FREE(buf);
            return VS_CODE_ERR_NO_MEMORY;
        }

        VS_IOT_MEMCPY(newbuf, buf, file_sz);
        VS_IOT_MEMCPY(newbuf + file_sz, fw_descr, sizeof(vs_update_fw_descriptor_t));
        file_sz += sizeof(vs_update_fw_descriptor_t);

        VS_IOT_FREE(buf);
    } else {
        file_sz = sizeof(vs_update_fw_descriptor_t);
        newbuf = VS_IOT_CALLOC(1, file_sz);
        CHECK_NOT_ZERO_RET(newbuf, VS_CODE_ERR_NO_MEMORY);
        VS_IOT_MEMCPY(newbuf, (uint8_t *)fw_descr, file_sz);
    }

save_data:
    res = _write_data(ctx, desc_id, 0, newbuf, file_sz);
    VS_IOT_FREE(newbuf);

    *file_size = fw_descr->firmware_length;

    return res;
}

/*************************************************************************/
static vs_status_code_e
_fw_set_data(void *context, const vs_update_file_type_t *file_type, const void *file_header, const void *file_data, size_t data_size, size_t data_offset){
    vs_storage_op_ctx_t *ctx = context;
    const vs_update_fw_descriptor_t *fw_descr = file_header;
    vs_storage_element_id_t data_id;
    (void) file_type;

    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_size, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_RET(data_offset < fw_descr->firmware_length, VS_CODE_ERR_ZERO_ARGUMENT, "Data offset %lu is bigger than file size %lu", data_offset, fw_descr->firmware_length);

    // cppcheck-suppress uninitvar
    _create_data_filename(fw_descr->info.manufacture_id, fw_descr->info.device_type, data_id);

    return _write_data(ctx, data_id, data_offset, file_data, data_size);

}

/*************************************************************************/
static vs_status_code_e
_fw_footer_save(const vs_storage_op_ctx_t *ctx, const vs_update_fw_descriptor_t *fw_descr, const uint8_t *file_footer){
    uint8_t i;
    vs_storage_element_id_t data_id;
    uint16_t footer_sz = sizeof(vs_update_fw_footer_t);
    const vs_update_fw_footer_t *fw_footer = (const vs_update_fw_footer_t *)file_footer;

    CHECK_NOT_ZERO_RET(fw_descr, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_data_filename(fw_descr->info.manufacture_id, fw_descr->info.device_type, data_id);

    for (i = 0; i < fw_footer->signatures_count; ++i) {
        int key_len;
        int sign_len;
        vs_sign_t *sign = (vs_sign_t *)(file_footer + footer_sz);

        sign_len = vs_hsm_get_signature_len(sign->ec_type);
        key_len = vs_hsm_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_CODE_ERR_INCORRECT_ARGUMENT, "Unsupported signature ec_type");

        footer_sz += sizeof(vs_sign_t) + sign_len + key_len;
    }

    return _write_data(ctx, data_id, fw_descr->firmware_length, file_footer, footer_sz);
}

/*************************************************************************/
static vs_status_code_e
_fw_verify(const vs_storage_op_ctx_t *ctx, const vs_update_fw_descriptor_t *fw_descr){
    vs_storage_element_id_t data_id;
    int file_sz;
    uint8_t *pubkey;
    uint16_t sign_len;
    uint16_t key_len;
    uint8_t sign_rules = 0;
    uint16_t i;
    vs_hsm_sw_sha256_ctx hash_ctx;
    vs_status_code_e ret_code;

    // TODO: Need to support all hash types
    uint8_t hash[32];

    CHECK_NOT_ZERO_RET(fw_descr, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_data_filename(fw_descr->info.manufacture_id, fw_descr->info.device_type, data_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, data_id);

    if (file_sz <= 0) {
        return VS_CODE_ERR_FILE;
    }

    int32_t footer_sz = file_sz - fw_descr->firmware_length;
    CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect footer size");

    uint8_t buf[fw_descr->chunk_size < footer_sz ? footer_sz : fw_descr->chunk_size];
    vs_update_fw_footer_t *footer = (vs_update_fw_footer_t *)buf;
    uint32_t offset = 0;
    size_t read_sz;

    vs_hsm_sw_sha256_init(&hash_ctx);

    // Update hash by firmware
    while (offset < fw_descr->firmware_length) {
        uint32_t fw_rest = fw_descr->firmware_length - offset;
        uint32_t required_chunk_size = fw_rest > fw_descr->chunk_size ? fw_descr->chunk_size : fw_rest;

        STATUS_CHECK_RET(_fw_get_data((void*)ctx, NULL, fw_descr, buf, required_chunk_size, &read_sz, offset), "Unable to get data while verifying firmware");

        vs_hsm_sw_sha256_update(&hash_ctx, buf, required_chunk_size);
        offset += required_chunk_size;
    }

    // Calculate fill size
    uint32_t fill_sz = fw_descr->app_size - fw_descr->firmware_length;
    CHECK_RET(footer_sz <= fill_sz, VS_CODE_ERR_VERIFY, "Bad fill size of image");
    fill_sz -= footer_sz;
    VS_IOT_MEMSET(buf, 0xFF, fw_descr->chunk_size > fill_sz ? fill_sz : fw_descr->chunk_size);

    // Update hash by fill
    while (fill_sz) {
        uint16_t sz = fw_descr->chunk_size > fill_sz ? fill_sz : fw_descr->chunk_size;
        vs_hsm_sw_sha256_update(&hash_ctx, buf, sz);
        fill_sz -= sz;
    }

    // Update hash by footer
    STATUS_CHECK_RET(_fw_get_footer((void*)ctx, NULL, fw_descr, buf, footer_sz, &read_sz), "Unable get hash by footer");

    vs_hsm_sw_sha256_update(&hash_ctx, buf, sizeof(vs_update_fw_footer_t));
    vs_hsm_sw_sha256_final(&hash_ctx, hash);

    // First signature
    vs_sign_t *sign = (vs_sign_t *)footer->signatures;

    CHECK_RET(footer->signatures_count >= VS_FW_SIGNATURES_QTY,
              VS_CODE_ERR_VERIFY,
              "There are not enough signatures");

    for (i = 0; i < footer->signatures_count; ++i) {
        CHECK_RET(sign->hash_type == VS_HASH_SHA_256, VS_CODE_ERR_VERIFY, "Unsupported hash size for sign FW");

        sign_len = vs_hsm_get_signature_len(sign->ec_type);
        key_len = vs_hsm_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_CODE_ERR_VERIFY, "Unsupported signature ec_type");

        // Signer raw key pointer
        pubkey = sign->raw_sign_pubkey + sign_len;

        CHECK_RET(vs_provision_search_hl_pubkey(sign->signer_type, sign->ec_type, pubkey, key_len),
                  VS_CODE_ERR_VERIFY,
                  "Signer key is wrong");

        if (_is_rule_equal_to(sign->signer_type)) {
            CHECK_RET(VS_HSM_ERR_OK == vs_hsm_ecdsa_verify(sign->ec_type,
                                                           pubkey,
                                                           key_len,
                                                           sign->hash_type,
                                                           hash,
                                                           sign->raw_sign_pubkey,
                                                           sign_len),
                      VS_CODE_ERR_VERIFY,
                      "Signature is wrong");
            sign_rules++;
        }

        // Next signature
        sign = (vs_sign_t *)(pubkey + key_len);
    }

    VS_LOG_DEBUG("New FW Image. Sign rules is %s", sign_rules >= VS_FW_SIGNATURES_QTY ? "correct" : "wrong");

    return sign_rules >= VS_FW_SIGNATURES_QTY ? VS_CODE_OK : VS_CODE_ERR_VERIFY;

}

/*************************************************************************/
static vs_status_code_e
_fw_delete(const vs_storage_op_ctx_t *ctx, const vs_update_fw_descriptor_t *fw_descr){
    int file_sz;
    vs_storage_element_id_t desc_id;
    vs_storage_element_id_t data_id;
    vs_status_code_e ret_code = VS_CODE_OK;

    uint8_t *buf = NULL;

    CHECK_NOT_ZERO_RET(fw_descr, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_fw_descr_filename(desc_id);
    
    // cppcheck-suppress uninitvar
    _create_data_filename(fw_descr->info.manufacture_id, fw_descr->info.device_type, data_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, desc_id);

    if (file_sz <= 0) {
        goto terminate;
    }

    uint16_t read_sz;
    uint32_t offset = 0;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NO_MEMORY);

    STATUS_CHECK(_read_data(ctx, desc_id, 0, buf, file_sz, &read_sz), "Unable to read data during firmware delete");

    while (offset < file_sz || offset + sizeof(vs_update_fw_descriptor_t) > file_sz) {
        vs_update_fw_descriptor_t *ptr = (vs_update_fw_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->info.manufacture_id, fw_descr->info.manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->info.device_type, fw_descr->info.device_type, DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMMOVE(buf + offset,
                           buf + offset + sizeof(vs_update_fw_descriptor_t),
                           file_sz - offset - sizeof(vs_update_fw_descriptor_t));
            file_sz -= sizeof(vs_update_fw_descriptor_t);
            break;
        }
        offset += sizeof(vs_update_fw_descriptor_t);
    }

    STATUS_CHECK(ctx->impl.del(ctx->storage_ctx, desc_id), "Error during firmware delete");

    if (file_sz) {
        ret_code = _write_data(ctx, desc_id, 0, buf, file_sz);
    }

    terminate:
    if (buf) {
        VS_IOT_FREE(buf);
    }

    if (VS_STORAGE_OK != ctx->impl.del(ctx->storage_ctx, data_id)) {
        return VS_CODE_ERR_FILE_DELETE;
    }

    return ret_code;
}

/*************************************************************************/
static vs_status_code_e
_fw_install(const vs_storage_op_ctx_t *ctx, const vs_update_fw_descriptor_t *fw_descr){
    vs_storage_element_id_t data_id;
    int file_sz;
    vs_status_code_e ret_code;

    CHECK_NOT_ZERO_RET(fw_descr, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(vs_update_install_prepare_space_hal(), "Unable to prepare the install space");

    // cppcheck-suppress uninitvar
    _create_data_filename(fw_descr->info.manufacture_id, fw_descr->info.device_type, data_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, data_id);

    if (file_sz <= 0) {
        return VS_CODE_ERR_FILE;
    }

    int32_t footer_sz = file_sz - fw_descr->firmware_length;
    CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect footer size");

    uint8_t buf[fw_descr->chunk_size < footer_sz ? footer_sz : fw_descr->chunk_size];
    uint32_t offset = 0;
    size_t read_sz;

    // Update image by firmware
    while (offset < fw_descr->firmware_length) {
        uint32_t fw_rest = fw_descr->firmware_length - offset;
        uint32_t required_chunk_size = fw_rest > fw_descr->chunk_size ? fw_descr->chunk_size : fw_rest;

        STATUS_CHECK_RET(_fw_get_data((void*)ctx, NULL, fw_descr, buf, required_chunk_size, &read_sz, offset),
            "Unable to get data while updating image by image");

        STATUS_CHECK_RET(vs_update_install_append_data_hal(buf, required_chunk_size),
            "Unable to append data while updating image by image");

        offset += required_chunk_size;
    }

    // Calculate fill size
    uint32_t fill_sz = fw_descr->app_size - fw_descr->firmware_length;
    CHECK_RET(footer_sz <= fill_sz, VS_CODE_ERR_FILE, "Bad fill size of image");
    fill_sz -= footer_sz;
    VS_IOT_MEMSET(buf, 0xFF, fw_descr->chunk_size > fill_sz ? fill_sz : fw_descr->chunk_size);

    // Update image by fill
    while (fill_sz) {
        uint16_t sz = fw_descr->chunk_size > fill_sz ? fill_sz : fw_descr->chunk_size;

        STATUS_CHECK_RET(vs_update_install_append_data_hal(buf, sz),
            "Unable to append data while updating image by fill");

        fill_sz -= sz;
    }

    // Update image by footer
    STATUS_CHECK_RET(_fw_get_footer((void*)ctx, NULL, fw_descr, buf, footer_sz, &read_sz),
                     "Unable to get footer while updating image by footer");

    return vs_update_install_append_data_hal(buf, read_sz);

}

/*************************************************************************/
static vs_status_code_e
_fw_set_footer(void *context, const vs_update_file_type_t *file_type, const void *file_header, const void *file_footer, size_t footer_size){
    vs_storage_op_ctx_t *ctx = context;
    const vs_update_fw_descriptor_t *fw_descr = file_header;
    vs_status_code_e res;
    (void) file_type;

    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_header, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(VS_CODE_OK == (res = _fw_footer_save(ctx, fw_descr, file_footer)), res,
            "Unable to save footer");

    if(VS_CODE_OK != _fw_verify(ctx, fw_descr)){
        VS_LOG_WARNING("Error while verifying firmware");

        if (VS_CODE_OK != (res = _fw_delete(ctx, fw_descr))) {
            VS_LOG_ERROR("Unable to delete firmware");
            return res;
        }

        return VS_CODE_ERR_VERIFY;

    } else {
        res = _fw_install(ctx, fw_descr);
    }

    return res;
}

/*************************************************************************/
static bool
_fw_file_is_newer(void *context, const vs_update_file_type_t *file_type, const vs_update_file_version_t *available_file, const vs_update_file_version_t *new_file){
    (void) context;
    (void) file_type;
    const vs_update_fw_version_t *fw_ver_available = (const vs_update_fw_version_t *) available_file;
    const vs_update_fw_version_t *fw_ver_new = (const vs_update_fw_version_t *) new_file;

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
_fw_free(void *context, const vs_update_file_type_t *file_type){
    vs_storage_op_ctx_t *ctx = (vs_storage_op_ctx_t *) context;
    (void) file_type;

    CHECK_NOT_ZERO(ctx);

    ctx->impl.deinit(ctx->storage_ctx);

    terminate:;
}

/*************************************************************************/
static vs_status_code_e
_fw_get_version(void *context, const vs_update_file_type_t *file_type, vs_update_file_version_t *file_version){
    vs_update_fw_descriptor_t fw_header;
    vs_status_code_e ret_code;
    size_t fw_header_size = sizeof(fw_header);

    CHECK_NOT_ZERO_RET(context, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_version, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(_fw_get_header(context, file_type, &fw_header, fw_header_size, &fw_header_size),     "Unable to get Firmware header");
    VS_IOT_ASSERT(fw_header_size == sizeof(fw_header));

    VS_IOT_MEMSET(&file_version->version, 0, sizeof(file_version->version));
    VS_IOT_MEMCPY(&file_version->version, &fw_header.info.version, sizeof(fw_header.info.version));

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_fw_get_header_size(void *context, const vs_update_file_type_t *file_type, size_t *header_size){
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO_RET(header_size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *header_size = sizeof(vs_update_fw_descriptor_t);

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_code_e
_fw_has_footer(void *context, const vs_update_file_type_t *file_type, bool *has_footer){
    (void) context;
    (void) file_type;

    CHECK_NOT_ZERO_RET(has_footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *has_footer = true;

    return VS_CODE_OK;
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

    update_ctx->get_version = _fw_get_version;
    update_ctx->get_header_size = _fw_get_header_size;
    update_ctx->has_footer = _fw_has_footer;
    update_ctx->get_header = _fw_get_header;
    update_ctx->get_data = _fw_get_data;
    update_ctx->get_footer = _fw_get_footer;
    update_ctx->set_header = _fw_set_header;
    update_ctx->set_data = _fw_set_data;
    update_ctx->set_footer = _fw_set_footer;
    update_ctx->file_is_newer = _fw_file_is_newer;
    update_ctx->free = _fw_free;
    update_ctx->describe_type = _fw_describe_type;
    update_ctx->describe_version = _fw_describe_version;
    update_ctx->file_context = storage_ctx;

    return VS_CODE_OK;
}