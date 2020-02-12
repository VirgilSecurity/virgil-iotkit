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

#include <update-config.h>
#include <endian-config.h>

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/firmware/firmware_hal.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

#include "private/firmware-private.h"

static const vs_key_type_e sign_rules_list[VS_FW_SIGNATURES_QTY] = VS_FW_SIGNER_TYPE_LIST;

#define DESCRIPTORS_FILENAME "firmware_descriptors"

static vs_storage_op_ctx_t *_storage_ctx = NULL;
static vs_secmodule_impl_t *_secmodule = NULL;

/*************************************************************************/
static void
_create_data_filename(const uint8_t manufacture_id[VS_DEVICE_MANUFACTURE_ID_SIZE],
                      const uint8_t device_type[VS_DEVICE_TYPE_SIZE],
                      vs_storage_element_id_t id) {
    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    VS_IOT_MEMCPY(&id[0], manufacture_id, VS_DEVICE_MANUFACTURE_ID_SIZE);
    VS_IOT_MEMCPY(&id[VS_DEVICE_MANUFACTURE_ID_SIZE], device_type, VS_DEVICE_TYPE_SIZE);
}

/*************************************************************************/
static void
_create_descriptors_filename(vs_storage_element_id_t id) {
    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    VS_IOT_MEMCPY(&id[0], DESCRIPTORS_FILENAME, sizeof(DESCRIPTORS_FILENAME));
}

/*************************************************************************/
static vs_status_e
_read_data(vs_storage_element_id_t id, uint32_t offset, uint8_t *data, ssize_t buff_sz, size_t *data_sz) {
    vs_storage_file_t f = NULL;
    ssize_t file_sz;
    ssize_t bytes_left;

    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.open, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.load, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.close, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *data_sz = 0;
    file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, id);

    CHECK_RET(0 < file_sz, VS_CODE_ERR_FILE, "Can't find file");
    CHECK_RET(file_sz >= offset, VS_CODE_ERR_FILE, "File format error");

    f = _storage_ctx->impl_func.open(_storage_ctx->impl_data, id);
    CHECK_RET(NULL != f, VS_CODE_ERR_FILE, "Can't open file");

    bytes_left = file_sz - offset;
    *data_sz = bytes_left > buff_sz ? buff_sz : bytes_left;
    if (VS_CODE_OK != _storage_ctx->impl_func.load(_storage_ctx->impl_data, f, offset, data, *data_sz)) {

        VS_LOG_ERROR("Can't load data from file");
        _storage_ctx->impl_func.close(_storage_ctx->impl_data, f);
        return VS_CODE_ERR_FILE_READ;
    }
    return _storage_ctx->impl_func.close(_storage_ctx->impl_data, f);
}

/******************************************************************************/
static vs_status_e
_write_data(vs_storage_element_id_t id, bool need_sync, uint32_t offset, const void *data, size_t data_sz) {
    vs_storage_file_t f = NULL;

    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.del, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.open, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.save, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.sync, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.close, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(data_sz <= _storage_ctx->file_sz_limit, VS_CODE_ERR_INCORRECT_ARGUMENT, "Requested size is too big");

    f = _storage_ctx->impl_func.open(_storage_ctx->impl_data, id);
    if (NULL == f) {
        VS_LOG_ERROR("Can't open file");
        return VS_CODE_ERR_FILE_WRITE;
    }

    if (VS_CODE_OK != _storage_ctx->impl_func.save(_storage_ctx->impl_data, f, offset, data, data_sz)) {
        _storage_ctx->impl_func.close(_storage_ctx->impl_data, f);
        VS_LOG_ERROR("Can't save data to file");
        return VS_CODE_ERR_FILE_WRITE;
    }

    if (need_sync) {
        int res = _storage_ctx->impl_func.sync(_storage_ctx->impl_data, f);
        CHECK_RET(VS_CODE_OK == res, res, "Can't sync file");
    }

    return _storage_ctx->impl_func.close(_storage_ctx->impl_data, f);
}

/******************************************************************************/
vs_status_e
vs_firmware_init(vs_storage_op_ctx_t *storage_ctx,
                 vs_secmodule_impl_t *secmodule,
                 vs_device_manufacture_id_t manufacture,
                 vs_device_type_t device_type,
                 vs_file_version_t *ver) {
    vs_status_e ret_code = VS_CODE_OK;
    vs_firmware_descriptor_t fw_descr;

    VS_IOT_ASSERT(ver);

    CHECK_NOT_ZERO_RET(ver, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx->impl_data, VS_CODE_ERR_NULLPTR_ARGUMENT);

    _storage_ctx = storage_ctx;
    _secmodule = secmodule;

    STATUS_CHECK_RET(vs_update_firmware_init(storage_ctx, manufacture, device_type),
                     "Unable to initialize Firmware module");

    STATUS_CHECK_RET(vs_firmware_get_own_firmware_descriptor(&fw_descr), "Unable to get own firmware descriptor");

    VS_LOG_DEBUG("Current Firmware version: %u.%u.%u.%u",
                 fw_descr.info.version.major,
                 fw_descr.info.version.minor,
                 fw_descr.info.version.patch,
                 fw_descr.info.version.build);

    *ver = fw_descr.info.version;

    return ret_code;
}

/******************************************************************************/
vs_status_e
vs_firmware_deinit(void) {
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.deinit, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return _storage_ctx->impl_func.deinit(_storage_ctx->impl_data);
}

/*************************************************************************/
vs_status_e
vs_firmware_load_firmware_chunk(const vs_firmware_descriptor_t *descriptor,
                                uint32_t offset,
                                uint8_t *data,
                                size_t buff_sz,
                                size_t *data_sz) {

    vs_storage_element_id_t data_id;
    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    return _read_data(data_id, offset, data, buff_sz, data_sz);
}

/*************************************************************************/
vs_status_e
vs_firmware_save_firmware_chunk(const vs_firmware_descriptor_t *descriptor,
                                const uint8_t *chunk,
                                size_t chunk_sz,
                                size_t offset) {

    vs_storage_element_id_t data_id;
    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(chunk, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    return _write_data(data_id, false, offset, chunk, chunk_sz);
}

/*************************************************************************/
vs_status_e
vs_firmware_save_firmware_footer(const vs_firmware_descriptor_t *descriptor, const uint8_t *footer) {
    uint8_t i;
    vs_storage_element_id_t data_id;
    size_t footer_sz = sizeof(vs_firmware_footer_t);
    vs_firmware_footer_t *f = (vs_firmware_footer_t *)footer;

    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    for (i = 0; i < f->signatures_count; ++i) {
        int key_len;
        int sign_len;
        vs_sign_t *sign = (vs_sign_t *)(footer + footer_sz);

        sign_len = vs_secmodule_get_signature_len(sign->ec_type);
        key_len = vs_secmodule_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_CODE_ERR_FILE, "Unsupported signature ec_type");

        footer_sz += sizeof(vs_sign_t) + sign_len + key_len;
    }

    return _write_data(data_id, true, descriptor->firmware_length, footer, footer_sz);
}

/*************************************************************************/
vs_status_e
vs_firmware_load_firmware_footer(const vs_firmware_descriptor_t *descriptor,
                                 uint8_t *data,
                                 size_t buff_sz,
                                 size_t *data_sz) {
    ssize_t file_sz;
    vs_storage_element_id_t data_id;

    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    *data_sz = 0;
    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, data_id);

    if (file_sz > 0) {

        int32_t footer_sz = file_sz - descriptor->firmware_length;
        CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_CODE_ERR_FORMAT_OVERFLOW, "Incorrect footer size");

        *data_sz = footer_sz;
        CHECK_RET(footer_sz <= buff_sz, VS_CODE_ERR_FILE, "Buffer to small");

        return _read_data(data_id, descriptor->firmware_length, data, footer_sz, data_sz);
    }
    return VS_CODE_ERR_FILE_READ;
}

/*************************************************************************/
vs_status_e
vs_firmware_save_firmware_descriptor(const vs_firmware_descriptor_t *descriptor) {
    ssize_t file_sz;
    vs_storage_element_id_t desc_id;
    uint8_t *buf = NULL;
    uint8_t *newbuf = NULL;
    uint32_t offset = 0;
    int res;

    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_descriptors_filename(desc_id);

    file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, desc_id);

    if (file_sz > 0) {
        size_t read_sz;
        buf = VS_IOT_CALLOC(1, file_sz);
        CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NO_MEMORY);

        if (VS_CODE_OK != _read_data(desc_id, 0, buf, file_sz, &read_sz)) {
            VS_IOT_FREE(buf);
            return VS_CODE_ERR_FILE_READ;
        }

        while (offset < file_sz) {
            if (offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
                file_sz = offset;
                break;
            }

            vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

            if (0 == memcmp(ptr->info.manufacture_id, descriptor->info.manufacture_id, VS_DEVICE_MANUFACTURE_ID_SIZE) &&
                0 == memcmp(ptr->info.device_type, descriptor->info.device_type, VS_DEVICE_TYPE_SIZE)) {
                VS_IOT_MEMCPY(ptr, descriptor, sizeof(vs_firmware_descriptor_t));
                newbuf = buf;
                goto save_data;
            }

            offset += sizeof(vs_firmware_descriptor_t);
        }

        newbuf = VS_IOT_CALLOC(1, file_sz + sizeof(vs_firmware_descriptor_t));

        if (NULL == newbuf) {
            VS_IOT_FREE(buf);
            return VS_CODE_ERR_NO_MEMORY;
        }

        VS_IOT_MEMCPY(newbuf, buf, file_sz);
        VS_IOT_MEMCPY(newbuf + file_sz, descriptor, sizeof(vs_firmware_descriptor_t));
        file_sz += sizeof(vs_firmware_descriptor_t);

        VS_IOT_FREE(buf);
    } else {
        file_sz = sizeof(vs_firmware_descriptor_t);
        newbuf = VS_IOT_CALLOC(1, file_sz);
        CHECK_NOT_ZERO_RET(newbuf, VS_CODE_ERR_NO_MEMORY);
        VS_IOT_MEMCPY(newbuf, (uint8_t *)descriptor, file_sz);
    }

save_data:
    res = _write_data(desc_id, true, 0, newbuf, file_sz);
    VS_IOT_FREE(newbuf);

    return res;
}

/*************************************************************************/
vs_status_e
vs_firmware_load_firmware_descriptor(const uint8_t manufacture_id[VS_DEVICE_MANUFACTURE_ID_SIZE],
                                     const uint8_t device_type[VS_DEVICE_TYPE_SIZE],
                                     vs_firmware_descriptor_t *descriptor) {

    vs_storage_element_id_t desc_id;
    int res = VS_CODE_ERR_NOT_FOUND;
    ssize_t file_sz;
    uint8_t *buf = NULL;
    uint32_t offset = 0;

    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_MEMSET(descriptor, 0, sizeof(*descriptor));

    // cppcheck-suppress uninitvar
    _create_descriptors_filename(desc_id);

    file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, desc_id);

    if (file_sz <= 0) {
        goto terminate;
    }

    size_t read_sz;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NO_MEMORY);

    if (VS_CODE_OK != _read_data(desc_id, 0, buf, file_sz, &read_sz)) {
        res = VS_CODE_ERR_FILE_READ;
        goto terminate;
    }

    while (offset + sizeof(vs_firmware_descriptor_t) <= file_sz) {
        vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->info.manufacture_id, manufacture_id, VS_DEVICE_MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->info.device_type, device_type, VS_DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMCPY(descriptor, ptr, sizeof(vs_firmware_descriptor_t));
            res = VS_CODE_OK;
            break;
        }

        offset += sizeof(vs_firmware_descriptor_t);
    }

terminate:
    VS_IOT_FREE(buf);

    return res;
}

/*************************************************************************/
vs_status_e
vs_firmware_delete_firmware(const vs_firmware_descriptor_t *descriptor) {
    int res = VS_CODE_ERR_NOT_FOUND;
    ssize_t file_sz;
    vs_storage_element_id_t desc_id;
    vs_storage_element_id_t data_id;

    uint8_t *buf = NULL;

    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.del, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_descriptors_filename(desc_id);
    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, desc_id);

    if (file_sz <= 0) {
        goto terminate;
    }

    size_t read_sz;
    uint32_t offset = 0;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NO_MEMORY);

    if (VS_CODE_OK != _read_data(desc_id, 0, buf, file_sz, &read_sz)) {
        res = VS_CODE_ERR_FILE_READ;
        goto terminate;
    }

    while (offset < file_sz || offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
        vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->info.manufacture_id, descriptor->info.manufacture_id, VS_DEVICE_MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->info.device_type, descriptor->info.device_type, VS_DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMMOVE(buf + offset,
                           buf + offset + sizeof(vs_firmware_descriptor_t),
                           file_sz - offset - sizeof(vs_firmware_descriptor_t));
            file_sz -= sizeof(vs_firmware_descriptor_t);
            break;
        }
        offset += sizeof(vs_firmware_descriptor_t);
    }

    if (VS_CODE_OK != _storage_ctx->impl_func.del(_storage_ctx->impl_data, desc_id)) {
        res = VS_CODE_ERR_FILE_DELETE;
        goto terminate;
    }

    res = VS_CODE_OK;
    if (file_sz) {
        res = _write_data(desc_id, true, 0, buf, file_sz);
    }

terminate:
    if (buf) {
        VS_IOT_FREE(buf);
    }

    if (VS_CODE_OK != _storage_ctx->impl_func.del(_storage_ctx->impl_data, data_id)) {
        return VS_CODE_ERR_FILE_DELETE;
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
vs_firmware_get_expected_footer_len(void) {
    uint16_t key_sz = vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    uint16_t sign_sz = (uint16_t)vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    return sizeof(vs_firmware_footer_t) + VS_FW_SIGNATURES_QTY * (sizeof(vs_sign_t) + key_sz + sign_sz);
}

/*************************************************************************/
vs_status_e
vs_firmware_get_own_firmware_descriptor(vs_firmware_descriptor_t *descriptor) {
    int footer_sz = vs_firmware_get_expected_footer_len();
    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(footer_sz > 0, VS_CODE_ERR_INCORRECT_ARGUMENT, "Can't get footer size");
    uint8_t buf[footer_sz];
    vs_status_e ret_code;
    vs_firmware_footer_t *own_footer = (vs_firmware_footer_t *)buf;

    STATUS_CHECK_RET(vs_firmware_get_own_firmware_footer_hal(buf, footer_sz), "Unable to read own firmware");

    vs_firmware_ntoh_descriptor(&own_footer->descriptor);
    VS_IOT_MEMCPY(descriptor, &own_footer->descriptor, sizeof(vs_firmware_descriptor_t));

    return VS_CODE_OK;
}

/*************************************************************************/
vs_status_e
vs_firmware_verify_firmware(const vs_firmware_descriptor_t *descriptor) {
    vs_storage_element_id_t data_id;
    ssize_t file_sz;
    uint8_t *pubkey;
    int sign_len;
    int key_len;
    uint8_t sign_rules = 0;
    uint16_t i;
    vs_secmodule_sw_sha256_ctx hash_ctx;
    vs_status_e ret_code;

    // TODO: Need to support all hash types
    uint8_t hash[VS_HASH_SHA256_LEN];

    VS_IOT_ASSERT(_secmodule);

    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, data_id);

    if (file_sz <= 0) {
        return VS_CODE_ERR_FILE;
    }

    int32_t footer_sz = file_sz - descriptor->firmware_length;
    CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_CODE_ERR_FORMAT_OVERFLOW, "Incorrect footer size");

    uint8_t buf[descriptor->chunk_size < footer_sz ? footer_sz : descriptor->chunk_size];
    vs_firmware_footer_t *footer = (vs_firmware_footer_t *)buf;
    uint32_t offset = 0;
    size_t read_sz;

    _secmodule->hash_init(&hash_ctx);

    // Update hash by firmware
    while (offset < descriptor->firmware_length) {
        uint32_t fw_rest = descriptor->firmware_length - offset;
        uint32_t required_chunk_size = fw_rest > descriptor->chunk_size ? descriptor->chunk_size : fw_rest;

        if (VS_CODE_OK != vs_firmware_load_firmware_chunk(descriptor, offset, buf, required_chunk_size, &read_sz)) {
            return VS_CODE_ERR_FILE_READ;
        }

        _secmodule->hash_update(&hash_ctx, buf, required_chunk_size);
        offset += required_chunk_size;
    }

    // Calculate fill size
    uint32_t fill_sz = descriptor->app_size - descriptor->firmware_length;
    CHECK_RET(footer_sz <= fill_sz, VS_CODE_ERR_INCORRECT_PARAMETER, "Bad fill size of image");
    fill_sz -= footer_sz;
    VS_IOT_MEMSET(buf, 0xFF, descriptor->chunk_size > fill_sz ? fill_sz : descriptor->chunk_size);

    // Update hash by fill
    while (fill_sz) {
        uint16_t sz = descriptor->chunk_size > fill_sz ? fill_sz : descriptor->chunk_size;
        _secmodule->hash_update(&hash_ctx, buf, sz);
        fill_sz -= sz;
    }

    // Update hash by footer
    if (VS_CODE_OK != vs_firmware_load_firmware_footer(descriptor, buf, footer_sz, &read_sz)) {
        return VS_CODE_ERR_FILE_READ;
    }

    _secmodule->hash_update(&hash_ctx, buf, sizeof(vs_firmware_footer_t));
    _secmodule->hash_finish(&hash_ctx, hash);

    // First signature
    vs_sign_t *sign = (vs_sign_t *)footer->signatures;

    CHECK_RET(footer->signatures_count >= VS_FW_SIGNATURES_QTY, VS_CODE_ERR_FILE, "There are not enough signatures");

    for (i = 0; i < footer->signatures_count; ++i) {
        CHECK_RET(sign->hash_type == VS_HASH_SHA_256, VS_CODE_ERR_UNSUPPORTED, "Unsupported hash size for sign FW");

        sign_len = vs_secmodule_get_signature_len(sign->ec_type);
        key_len = vs_secmodule_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_CODE_ERR_UNSUPPORTED, "Unsupported signature ec_type");

        // Signer raw key pointer
        pubkey = sign->raw_sign_pubkey + (uint16_t)sign_len;

        STATUS_CHECK_RET(vs_provision_search_hl_pubkey(sign->signer_type, sign->ec_type, pubkey, (uint16_t)key_len),
                         "Signer key is wrong");

        if (_is_rule_equal_to(sign->signer_type)) {
            STATUS_CHECK_RET(_secmodule->ecdsa_verify(sign->ec_type,
                                                      pubkey,
                                                      (uint16_t)key_len,
                                                      sign->hash_type,
                                                      hash,
                                                      sign->raw_sign_pubkey,
                                                      (uint16_t)sign_len),
                             "Signature is wrong");
            sign_rules++;
        }

        // Next signature
        sign = (vs_sign_t *)(pubkey + (uint16_t)key_len);
    }

    VS_LOG_DEBUG("New FW Image. Sign rules is %s", sign_rules >= VS_FW_SIGNATURES_QTY ? "correct" : "wrong");

    return sign_rules >= VS_FW_SIGNATURES_QTY ? VS_CODE_OK : VS_CODE_ERR_VERIFY;
}

/*************************************************************************/
vs_status_e
vs_firmware_compare_own_version(const vs_firmware_descriptor_t *new_descriptor) {
    vs_firmware_descriptor_t own_desc;

    CHECK_NOT_ZERO_RET(new_descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(VS_CODE_OK == vs_firmware_get_own_firmware_descriptor(&own_desc),
              VS_CODE_ERR_NOT_FOUND,
              "Unable to get own firmware descriptor");

    if (0 != VS_IOT_MEMCMP(own_desc.info.manufacture_id,
                           new_descriptor->info.manufacture_id,
                           VS_DEVICE_MANUFACTURE_ID_SIZE) &&
        0 != VS_IOT_MEMCMP(own_desc.info.device_type, new_descriptor->info.device_type, VS_DEVICE_TYPE_SIZE)) {
        VS_LOG_DEBUG("The new firmware descriptor is not own");
        return VS_CODE_ERR_NOT_FOUND;
    }


    return vs_update_compare_version(&new_descriptor->info.version, &own_desc.info.version);
}

/*************************************************************************/
vs_status_e
vs_firmware_install_firmware(const vs_firmware_descriptor_t *descriptor) {
    vs_storage_element_id_t data_id;
    vs_status_e ret_code;
    ssize_t file_sz;

    CHECK_NOT_ZERO_RET(descriptor, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx->impl_func.size, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Compare the own firmware image version
    ret_code = vs_firmware_compare_own_version(descriptor);
    if (VS_CODE_OLD_VERSION == ret_code) {
        VS_LOG_WARNING("No need to install a new firmware. It doesn't contain a new version");
        return VS_CODE_ERR_VERIFY;
    }
    CHECK_RET(VS_CODE_OK == ret_code, VS_CODE_ERR_VERIFY, "Error during checking own firmware version");

    CHECK_RET(VS_CODE_OK == vs_firmware_install_prepare_space_hal(),
              VS_CODE_ERR_FILE,
              "Unable to prepare the install space");

    // cppcheck-suppress uninitvar
    _create_data_filename(descriptor->info.manufacture_id, descriptor->info.device_type, data_id);

    file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, data_id);

    if (file_sz <= 0) {
        return VS_CODE_ERR_FILE;
    }

    int32_t footer_sz = file_sz - descriptor->firmware_length;
    CHECK_RET(footer_sz > 0 && footer_sz < UINT16_MAX, VS_CODE_ERR_FORMAT_OVERFLOW, "Incorrect footer size");

    uint8_t buf[descriptor->chunk_size < footer_sz ? footer_sz : descriptor->chunk_size];
    uint32_t offset = 0;
    size_t read_sz;

    // Update image by firmware
    while (offset < descriptor->firmware_length) {
        uint32_t fw_rest = descriptor->firmware_length - offset;
        uint32_t required_chunk_size = fw_rest > descriptor->chunk_size ? descriptor->chunk_size : fw_rest;

        STATUS_CHECK_RET(vs_firmware_load_firmware_chunk(descriptor, offset, buf, required_chunk_size, &read_sz),
                         "Unable to load data chunk");
        STATUS_CHECK_RET(vs_firmware_install_append_data_hal(buf, required_chunk_size), "Unable to append data");

        offset += required_chunk_size;
    }

    // Calculate fill size
    uint32_t fill_sz = descriptor->app_size - descriptor->firmware_length;
    CHECK_RET(footer_sz <= fill_sz, VS_CODE_ERR_FILE, "Bad fill size of image");
    fill_sz -= footer_sz;
    VS_IOT_MEMSET(buf, 0xFF, descriptor->chunk_size > fill_sz ? fill_sz : descriptor->chunk_size);

    // Update image by fill
    while (fill_sz) {
        uint16_t sz = descriptor->chunk_size > fill_sz ? fill_sz : descriptor->chunk_size;

        STATUS_CHECK_RET(VS_CODE_OK != vs_firmware_install_append_data_hal(buf, sz),
                         "Unable to install and append data");

        fill_sz -= sz;
    }

    // Update image by footer
    STATUS_CHECK_RET(vs_firmware_load_firmware_footer(descriptor, buf, footer_sz, &read_sz),
                     "Unable to load firmware footer");

    STATUS_CHECK_RET(vs_firmware_install_append_data_hal(buf, read_sz), "Unable to append data");

    return ret_code;
}

/*************************************************************************/
void
vs_firmware_ntoh_descriptor(vs_firmware_descriptor_t *desc) {
    VS_IOT_ASSERT(desc);

    desc->chunk_size = VS_IOT_NTOHS(desc->chunk_size);
    desc->app_size = VS_IOT_NTOHL(desc->app_size);
    desc->firmware_length = VS_IOT_NTOHL(desc->firmware_length);
    desc->info.version.timestamp = VS_IOT_NTOHL(desc->info.version.timestamp);
    desc->info.version.build = VS_IOT_NTOHL(desc->info.version.build);
}

/*************************************************************************/
void
vs_firmware_ntoh_header(vs_firmware_header_t *header) {
    VS_IOT_ASSERT(header);

    vs_firmware_ntoh_descriptor(&header->descriptor);

    header->code_length = VS_IOT_NTOHL(header->code_length);
    header->code_offset = VS_IOT_NTOHL(header->code_offset);
    header->footer_length = VS_IOT_NTOHL(header->footer_length);
    header->footer_offset = VS_IOT_NTOHL(header->footer_offset);
}

/*************************************************************************/
void
vs_firmware_hton_descriptor(vs_firmware_descriptor_t *desc) {
    VS_IOT_ASSERT(desc);
    desc->chunk_size = VS_IOT_HTONS(desc->chunk_size);
    desc->app_size = VS_IOT_HTONL(desc->app_size);
    desc->firmware_length = VS_IOT_HTONL(desc->firmware_length);
    desc->info.version.timestamp = VS_IOT_HTONL(desc->info.version.timestamp);
    desc->info.version.build = VS_IOT_HTONL(desc->info.version.build);
}

/*************************************************************************/
void
vs_firmware_hton_header(vs_firmware_header_t *header) {
    VS_IOT_ASSERT(header);

    vs_firmware_hton_descriptor(&header->descriptor);

    header->code_length = VS_IOT_HTONL(header->code_length);
    header->code_offset = VS_IOT_HTONL(header->code_offset);
    header->footer_length = VS_IOT_HTONL(header->footer_length);
    header->footer_offset = VS_IOT_HTONL(header->footer_offset);
}

/*************************************************************************/
