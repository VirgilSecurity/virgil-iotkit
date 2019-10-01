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
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/firmware/firmware_hal.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/hsm/hsm_sw_sha2_routines.h>

static const vs_key_type_e sign_rules_list[VS_FW_SIGNATURES_QTY] = VS_FW_SIGNER_TYPE_LIST;

#define DESCRIPTORS_FILENAME "firmware_descriptors"

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
_create_descriptors_filename(vs_storage_element_id_t id) {
    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    VS_IOT_MEMCPY(&id[0], DESCRIPTORS_FILENAME, sizeof(DESCRIPTORS_FILENAME));
}

/*************************************************************************/
static int
_read_data(const vs_storage_op_ctx_t *ctx,
           vs_storage_element_id_t id,
           uint32_t offset,
           uint8_t *data,
           size_t buff_sz,
           size_t *data_sz) {
    vs_storage_file_t f = NULL;
    int file_sz;
    size_t bytes_left;

    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.load, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.close, VS_STORAGE_ERROR_PARAMS);

    *data_sz = 0;
    file_sz = ctx->impl.size(ctx->storage_ctx, id);

    CHECK_RET(0 < file_sz, VS_STORAGE_ERROR_GENERAL, "Can't find file");
    CHECK_RET(file_sz >= offset, VS_STORAGE_ERROR_GENERAL, "File format error");

    f = ctx->impl.open(ctx->storage_ctx, id);
    CHECK_RET(NULL != f, VS_STORAGE_ERROR_GENERAL, "Can't open file");

    bytes_left = file_sz - offset;
    *data_sz = bytes_left > buff_sz ? buff_sz : bytes_left;
    if (VS_STORAGE_OK != ctx->impl.load(ctx->storage_ctx, f, offset, data, *data_sz)) {

        VS_LOG_ERROR("Can't load data from file");
        ctx->impl.close(ctx->storage_ctx, f);
        return VS_STORAGE_ERROR_GENERAL;
    }
    return ctx->impl.close(ctx->storage_ctx, f);
}

/******************************************************************************/
static int
_write_data(const vs_storage_op_ctx_t *ctx,
            vs_storage_element_id_t id,
            uint32_t offset,
            const void *data,
            size_t data_sz) {
    vs_storage_file_t f = NULL;

    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.del, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.save, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.close, VS_STORAGE_ERROR_PARAMS);
    CHECK_RET(data_sz <= ctx->file_sz_limit, VS_STORAGE_ERROR_PARAMS, "Requested size is too big");

    f = ctx->impl.open(ctx->storage_ctx, id);
    if (NULL == f) {
        VS_LOG_ERROR("Can't open file");
        return VS_STORAGE_ERROR_WRITE;
    }

    if (VS_STORAGE_OK != ctx->impl.save(ctx->storage_ctx, f, offset, data, data_sz)) {
        ctx->impl.close(ctx->storage_ctx, f);
        VS_LOG_ERROR("Can't save data to file");
        return VS_STORAGE_ERROR_WRITE;
    }

    return ctx->impl.close(ctx->storage_ctx, f);
}

/******************************************************************************/
int
vs_firmware_init(const vs_storage_op_ctx_t *ctx) {
    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);

    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_firnware_deinit(const vs_storage_op_ctx_t *ctx) {
    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.deinit, VS_STORAGE_ERROR_PARAMS);

    return ctx->impl.deinit(ctx->storage_ctx);
}

/*************************************************************************/
int
vs_firmware_load_firmware_chunk(const vs_storage_op_ctx_t *ctx,
                              const vs_firmware_descriptor_t *descriptor,
                              uint32_t offset,
                              uint8_t *data,
                              size_t buff_sz,
                              size_t *data_sz) {

    vs_storage_element_id_t data_id;
    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(data, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(data_sz, VS_STORAGE_ERROR_PARAMS);

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    return _read_data(ctx, data_id, offset, data, buff_sz, data_sz);
}

/*************************************************************************/
int
vs_firmware_save_firmware_chunk(const vs_storage_op_ctx_t *ctx,
                              const vs_firmware_descriptor_t *descriptor,
                              const uint8_t *chunk,
                              size_t chunk_sz,
                              size_t offset) {

    vs_storage_element_id_t data_id;
    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(chunk, VS_STORAGE_ERROR_PARAMS);

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    return _write_data(ctx, data_id, offset, chunk, chunk_sz);
}

/*************************************************************************/
int
vs_firmware_save_firmware_footer(const vs_storage_op_ctx_t *ctx, const vs_firmware_descriptor_t *descriptor, const uint8_t *footer) {
    uint8_t i;
    vs_storage_element_id_t data_id;
    size_t footer_sz = sizeof(vs_firmware_footer_t);
    vs_firmware_footer_t *f = (vs_firmware_footer_t *)footer;

    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(footer, VS_STORAGE_ERROR_PARAMS);

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    for (i = 0; i < f->signatures_count; ++i) {
        int key_len;
        int sign_len;
        vs_sign_t *sign = (vs_sign_t *)(footer + footer_sz);

        sign_len = vs_hsm_get_signature_len(sign->ec_type);
        key_len = vs_hsm_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_STORAGE_ERROR_PARAMS, "Unsupported signature ec_type");

        footer_sz += sizeof(vs_sign_t) + sign_len + key_len;
    }

    return _write_data(ctx, data_id, descriptor->firmware_length, footer, footer_sz);
}

/*************************************************************************/
int
vs_firmware_load_firmware_footer(const vs_storage_op_ctx_t *ctx,
                               const vs_firmware_descriptor_t *descriptor,
                               uint8_t *data,
                                 size_t buff_sz,
                                 size_t *data_sz) {
    int file_sz;
    vs_storage_element_id_t data_id;

    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(data, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(data_sz, VS_STORAGE_ERROR_PARAMS);

    *data_sz = 0;
    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, data_id);

    if (file_sz > 0) {

        int32_t footer_sz = file_sz - descriptor->firmware_length;
        CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_STORAGE_ERROR_PARAMS, "Incorrect footer size");

        *data_sz = footer_sz;
        CHECK_RET(footer_sz <= buff_sz, VS_STORAGE_ERROR_PARAMS, "Buffer to small");

        return _read_data(ctx, data_id, descriptor->firmware_length, data, footer_sz, data_sz);
    }
    return VS_STORAGE_ERROR_READ;
}

/*************************************************************************/
int
vs_firmware_save_firmware_descriptor(const vs_storage_op_ctx_t *ctx, const vs_firmware_descriptor_t *descriptor) {
    int file_sz;
    vs_storage_element_id_t desc_id;
    uint8_t *buf = NULL;
    uint8_t *newbuf = NULL;
    uint32_t offset = 0;
    int res;

    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);

    // cppcheck-suppress uninitvar
    _create_descriptors_filename(desc_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, desc_id);

    if (file_sz > 0) {
        size_t read_sz;
        buf = VS_IOT_CALLOC(1, file_sz);
        CHECK_NOT_ZERO_RET(buf, VS_STORAGE_ERROR_GENERAL);

        if (VS_STORAGE_OK != _read_data(ctx, desc_id, 0, buf, file_sz, &read_sz)) {
            VS_IOT_FREE(buf);
            return VS_STORAGE_ERROR_READ;
        }

        while (offset < file_sz) {
            if (offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
                file_sz = offset;
                break;
            }

            vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

            if (0 == memcmp(ptr->info.manufacture_id, descriptor->info.manufacture_id, MANUFACTURE_ID_SIZE) &&
                0 == memcmp(ptr->info.device_type, descriptor->info.device_type, DEVICE_TYPE_SIZE)) {
                VS_IOT_MEMCPY(ptr, descriptor, sizeof(vs_firmware_descriptor_t));
                newbuf = buf;
                goto save_data;
            }

            offset += sizeof(vs_firmware_descriptor_t);
        }

        newbuf = VS_IOT_CALLOC(1, file_sz + sizeof(vs_firmware_descriptor_t));

        if (NULL == newbuf) {
            VS_IOT_FREE(buf);
            return VS_STORAGE_ERROR_GENERAL;
        }

        VS_IOT_MEMCPY(newbuf, buf, file_sz);
        VS_IOT_MEMCPY(newbuf + file_sz, descriptor, sizeof(vs_firmware_descriptor_t));
        file_sz += sizeof(vs_firmware_descriptor_t);

        VS_IOT_FREE(buf);
    } else {
        file_sz = sizeof(vs_firmware_descriptor_t);
        newbuf = VS_IOT_CALLOC(1, file_sz);
        CHECK_NOT_ZERO_RET(newbuf, VS_STORAGE_ERROR_GENERAL);
        VS_IOT_MEMCPY(newbuf, (uint8_t *)descriptor, file_sz);
    }

    save_data:
    res = _write_data(ctx, desc_id, 0, newbuf, file_sz);
    VS_IOT_FREE(newbuf);

    return res;
}

/*************************************************************************/
int
vs_firmware_load_firmware_descriptor(const vs_storage_op_ctx_t *ctx,
                                   const uint8_t manufacture_id[MANUFACTURE_ID_SIZE],
                                   const uint8_t device_type[DEVICE_TYPE_SIZE],
                                   vs_firmware_descriptor_t *descriptor) {

    vs_storage_element_id_t desc_id;
    int res = VS_STORAGE_ERROR_NOT_FOUND;
    int file_sz;
    uint8_t *buf = NULL;
    uint32_t offset = 0;

    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);

    // cppcheck-suppress uninitvar
    _create_descriptors_filename(desc_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, desc_id);

    if (file_sz <= 0) {
        goto terminate;
    }

    size_t read_sz;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO_RET(buf, VS_STORAGE_ERROR_GENERAL);

    if (VS_STORAGE_OK != _read_data(ctx, desc_id, 0, buf, file_sz, &read_sz)) {
        res = VS_STORAGE_ERROR_READ;
        goto terminate;
    }

    while (offset + sizeof(vs_firmware_descriptor_t) <= file_sz) {
        vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->info.manufacture_id, manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->info.device_type, device_type, DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMCPY(descriptor, ptr, sizeof(vs_firmware_descriptor_t));
            res = VS_STORAGE_OK;
            break;
        }

        offset += sizeof(vs_firmware_descriptor_t);
    }

    terminate:
    VS_IOT_FREE(buf);

    return res;
}

/*************************************************************************/
int
vs_firmware_delete_firmware(const vs_storage_op_ctx_t *ctx, const vs_firmware_descriptor_t *descriptor) {
    int res = VS_STORAGE_ERROR_NOT_FOUND;
    int file_sz;
    vs_storage_element_id_t desc_id;
    vs_storage_element_id_t data_id;

    uint8_t *buf = NULL;

    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.del, VS_STORAGE_ERROR_PARAMS);

    // cppcheck-suppress uninitvar
    _create_descriptors_filename(desc_id);
    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, desc_id);

    if (file_sz <= 0) {
        goto terminate;
    }

    size_t read_sz;
    uint32_t offset = 0;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO_RET(buf, VS_STORAGE_ERROR_GENERAL);

    if (VS_STORAGE_OK != _read_data(ctx, desc_id, 0, buf, file_sz, &read_sz)) {
        res = VS_STORAGE_ERROR_GENERAL;
        goto terminate;
    }

    while (offset < file_sz || offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
        vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->info.manufacture_id, descriptor->info.manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->info.device_type, descriptor->info.device_type, DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMMOVE(buf + offset,
                           buf + offset + sizeof(vs_firmware_descriptor_t),
                           file_sz - offset - sizeof(vs_firmware_descriptor_t));
            file_sz -= sizeof(vs_firmware_descriptor_t);
            break;
        }
        offset += sizeof(vs_firmware_descriptor_t);
    }

    if (VS_STORAGE_OK != ctx->impl.del(ctx->storage_ctx, desc_id)) {
        res = VS_STORAGE_ERROR_GENERAL;
        goto terminate;
    }

    res = VS_STORAGE_OK;
    if (file_sz) {
        res = _write_data(ctx, desc_id, 0, buf, file_sz);
    }

    terminate:
    if (buf) {
        VS_IOT_FREE(buf);
    }

    if (VS_STORAGE_OK != ctx->impl.del(ctx->storage_ctx, data_id)) {
        return VS_STORAGE_ERROR_GENERAL;
    }

    return res;
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
int
vs_firmware_verify_firmware(const vs_storage_op_ctx_t *ctx, const vs_firmware_descriptor_t *descriptor) {
    vs_storage_element_id_t data_id;
    int file_sz;
    uint8_t *pubkey;
    uint16_t sign_len;
    uint16_t key_len;
    uint8_t sign_rules = 0;
    uint16_t i;
    vs_hsm_sw_sha256_ctx hash_ctx;

    // TODO: Need to support all hash types
    uint8_t hash[32];

    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, data_id);

    if (file_sz <= 0) {
        return VS_STORAGE_ERROR_GENERAL;
    }

    int32_t footer_sz = file_sz - descriptor->firmware_length;
    CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_STORAGE_ERROR_PARAMS, "Incorrect footer size");

    uint8_t buf[descriptor->chunk_size < footer_sz ? footer_sz : descriptor->chunk_size];
    vs_firmware_footer_t *footer = (vs_firmware_footer_t *)buf;
    uint32_t offset = 0;
    size_t read_sz;

    vs_hsm_sw_sha256_init(&hash_ctx);

    // Update hash by firmware
    while (offset < descriptor->firmware_length) {
        uint32_t fw_rest = descriptor->firmware_length - offset;
        uint32_t required_chunk_size = fw_rest > descriptor->chunk_size ? descriptor->chunk_size : fw_rest;

        if (VS_STORAGE_OK !=
            vs_firmware_load_firmware_chunk(ctx, descriptor, offset, buf, required_chunk_size, &read_sz)) {
            return VS_STORAGE_ERROR_GENERAL;
        }

        vs_hsm_sw_sha256_update(&hash_ctx, buf, required_chunk_size);
        offset += required_chunk_size;
    }

    // Calculate fill size
    uint32_t fill_sz = descriptor->app_size - descriptor->firmware_length;
    CHECK_RET(footer_sz <= fill_sz, VS_STORAGE_ERROR_GENERAL, "Bad fill size of image");
    fill_sz -= footer_sz;
    VS_IOT_MEMSET(buf, 0xFF, descriptor->chunk_size > fill_sz ? fill_sz : descriptor->chunk_size);

    // Update hash by fill
    while (fill_sz) {
        uint16_t sz = descriptor->chunk_size > fill_sz ? fill_sz : descriptor->chunk_size;
        vs_hsm_sw_sha256_update(&hash_ctx, buf, sz);
        fill_sz -= sz;
    }

    // Update hash by footer
    if (VS_STORAGE_OK != vs_firmware_load_firmware_footer(ctx, descriptor, buf, footer_sz, &read_sz)) {
        return VS_STORAGE_ERROR_READ;
    }

    vs_hsm_sw_sha256_update(&hash_ctx, buf, sizeof(vs_firmware_footer_t));
    vs_hsm_sw_sha256_final(&hash_ctx, hash);

    // First signature
    vs_sign_t *sign = (vs_sign_t *)footer->signatures;

    CHECK_RET(footer->signatures_count >= VS_FW_SIGNATURES_QTY,
              VS_STORAGE_ERROR_GENERAL,
              "There are not enough signatures");

    for (i = 0; i < footer->signatures_count; ++i) {
        CHECK_RET(sign->hash_type == VS_HASH_SHA_256, VS_STORAGE_ERROR_GENERAL, "Unsupported hash size for sign FW");

        sign_len = vs_hsm_get_signature_len(sign->ec_type);
        key_len = vs_hsm_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_STORAGE_ERROR_GENERAL, "Unsupported signature ec_type");

        // Signer raw key pointer
        pubkey = sign->raw_sign_pubkey + sign_len;

        CHECK_RET(vs_provision_search_hl_pubkey(sign->signer_type, sign->ec_type, pubkey, key_len),
                  VS_STORAGE_ERROR_GENERAL,
                  "Signer key is wrong");

        if (_is_rule_equal_to(sign->signer_type)) {
            CHECK_RET(VS_HSM_ERR_OK == vs_hsm_ecdsa_verify(sign->ec_type,
                                                           pubkey,
                                                           key_len,
                                                           sign->hash_type,
                                                           hash,
                                                           sign->raw_sign_pubkey,
                                                           sign_len),
                      VS_STORAGE_ERROR_GENERAL,
                      "Signature is wrong");
            sign_rules++;
        }

        // Next signature
        sign = (vs_sign_t *)(pubkey + key_len);
    }

    VS_LOG_DEBUG("New FW Image. Sign rules is %s", sign_rules >= VS_FW_SIGNATURES_QTY ? "correct" : "wrong");

    return sign_rules >= VS_FW_SIGNATURES_QTY ? VS_STORAGE_OK : VS_STORAGE_ERROR_GENERAL;
}

/*************************************************************************/
int
vs_firmware_install_firmware(const vs_storage_op_ctx_t *ctx, const vs_firmware_descriptor_t *descriptor) {
    vs_storage_element_id_t data_id;
    int file_sz;

    CHECK_NOT_ZERO_RET(descriptor, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);

    CHECK_RET(VS_STORAGE_OK == vs_firmware_install_prepare_space_hal(),
              VS_STORAGE_ERROR_GENERAL,
              "Unable to prepare the install space");

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    file_sz = ctx->impl.size(ctx->storage_ctx, data_id);

    if (file_sz <= 0) {
        return VS_STORAGE_ERROR_GENERAL;
    }

    int32_t footer_sz = file_sz - descriptor->firmware_length;
    CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_STORAGE_ERROR_PARAMS, "Incorrect footer size");

    uint8_t buf[descriptor->chunk_size < footer_sz ? footer_sz : descriptor->chunk_size];
    uint32_t offset = 0;
    size_t read_sz;

    // Update image by firmware
    while (offset < descriptor->firmware_length) {
        uint32_t fw_rest = descriptor->firmware_length - offset;
        uint32_t required_chunk_size = fw_rest > descriptor->chunk_size ? descriptor->chunk_size : fw_rest;

        if (VS_STORAGE_OK !=
            vs_firmware_load_firmware_chunk(ctx, descriptor, offset, buf, required_chunk_size, &read_sz)) {
            return VS_STORAGE_ERROR_GENERAL;
        }

        if (VS_STORAGE_OK != vs_firmware_install_append_data_hal(buf, required_chunk_size)) {
            return VS_STORAGE_ERROR_GENERAL;
        }

        offset += required_chunk_size;
    }

    // Calculate fill size
    uint32_t fill_sz = descriptor->app_size - descriptor->firmware_length;
    CHECK_RET(footer_sz <= fill_sz, VS_STORAGE_ERROR_GENERAL, "Bad fill size of image");
    fill_sz -= footer_sz;
    VS_IOT_MEMSET(buf, 0xFF, descriptor->chunk_size > fill_sz ? fill_sz : descriptor->chunk_size);

    // Update image by fill
    while (fill_sz) {
        uint16_t sz = descriptor->chunk_size > fill_sz ? fill_sz : descriptor->chunk_size;

        if (VS_STORAGE_OK != vs_firmware_install_append_data_hal(buf, sz)) {
            return VS_STORAGE_ERROR_GENERAL;
        }

        fill_sz -= sz;
    }

    // Update image by footer
    if (VS_STORAGE_OK != vs_firmware_load_firmware_footer(ctx, descriptor, buf, footer_sz, &read_sz)) {
        return VS_STORAGE_ERROR_GENERAL;
    }

    return vs_firmware_install_append_data_hal(buf, read_sz);
}

/*************************************************************************/
char *
vs_firmware_describe_version(const vs_firmware_version_t *fw_ver, char *buffer, size_t buf_size){
    static const uint32_t START_EPOCH = 1420070400; // January 1, 2015 UTC

    CHECK_NOT_ZERO_RET(fw_ver, NULL);
    CHECK_NOT_ZERO_RET(buffer, NULL);
    CHECK_NOT_ZERO_RET(buf_size, NULL);

#ifdef VS_IOT_ASCTIME
    time_t timestamp = fw_ver->timestamp + START_EPOCH;
#else
    uint32_t timestamp = fw_ver->timestamp + START_EPOCH;
#endif //   VS_IOT_ASCTIME

    VS_IOT_SNPRINTF(buffer, buf_size,
                    #ifdef VS_IOT_ASCTIME
                            "ver %d.%d.%d.%c.%d, %s",
                    #else
                            "ver %d.%d.%d.%c.%d, UNIX timestamp %u",
                    #endif //   VS_IOT_ASCTIME
                            fw_ver->major,
                    fw_ver->minor,
                    fw_ver->patch,
                    fw_ver->dev_milestone,
                    fw_ver->dev_build,
                    #ifdef VS_IOT_ASCTIME
                            fw_ver->timestamp ? VS_IOT_ASCTIME(timestamp) : "0"
#else
            timestamp
#endif //   VS_IOT_ASCTIME
    );

    return buffer;
}
