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

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/update/update_interface.h>
#include <virgil/iot/logger/logger.h>

#include <virgil/iot/provision/provision.h>
#include <virgil/iot/hsm/hsm_helpers.h>

/*************************************************************************/
int
vs_update_load_firmware_chunk(vs_firmware_descriptor_t *descriptor,
                              uint32_t offset,
                              uint8_t *data,
                              uint16_t buff_sz,
                              uint16_t *data_sz) {


    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data_sz, VS_UPDATE_ERR_INVAL);

    return vs_update_read_firmware_data_hal(
            descriptor->manufacture_id, descriptor->device_type, offset, data, buff_sz, data_sz);
}

/*************************************************************************/
int
vs_update_save_firmware_chunk(vs_firmware_descriptor_t *descriptor,
                              uint8_t *chunk,
                              uint16_t chunk_sz,
                              uint32_t offset) {

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(chunk, VS_UPDATE_ERR_INVAL);

    return vs_update_write_firmware_data_hal(
            descriptor->manufacture_id, descriptor->device_type, offset, chunk, chunk_sz);
}

/*************************************************************************/
int
vs_update_save_firmware_footer(vs_firmware_descriptor_t *descriptor, uint8_t *footer) {
    uint16_t footer_sz = sizeof(vs_update_firmware_footer_t);
    vs_update_firmware_footer_t *f = (vs_update_firmware_footer_t *)footer;

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(footer, VS_UPDATE_ERR_INVAL);

    for (uint8_t i = 0; i < f->signatures_count; ++i) {
        int key_len;
        int sign_len;
        vs_sign_t *sign = (vs_sign_t *)(footer + footer_sz);

        sign_len = vs_hsm_get_signature_len(sign->ec_type);
        key_len = vs_hsm_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_UPDATE_ERR_INVAL, "Unsupported signature ec_type")

        footer_sz += sizeof(vs_sign_t) + sign_len + key_len;
    }

    return vs_update_write_firmware_data_hal(
            descriptor->manufacture_id, descriptor->device_type, descriptor->firmware_length, footer, footer_sz);
}

/*************************************************************************/
int
vs_update_load_firmware_footer(vs_firmware_descriptor_t *descriptor,
                               uint8_t *data,
                               uint16_t buff_sz,
                               uint16_t *data_sz) {
    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data_sz, VS_UPDATE_ERR_INVAL);

    return vs_update_read_firmware_data_hal(
            descriptor->manufacture_id, descriptor->device_type, descriptor->firmware_length, data, buff_sz, data_sz);
}

/*************************************************************************/
int
vs_update_save_firmware_descriptor(vs_firmware_descriptor_t *descriptor) {
    int file_sz;
    uint8_t *buf = NULL;
    uint32_t offset = 0;

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);

    file_sz = vs_update_get_firmware_descriptor_table_len_hal();

    if (file_sz > 0) {
        uint16_t read_sz;
        buf = VS_IOT_CALLOC(1, file_sz);
        CHECK_NOT_ZERO(buf, VS_UPDATE_ERR_FAIL);

        if (VS_UPDATE_ERR_OK != vs_update_read_firmware_descriptor_table_hal(buf, file_sz, &read_sz)) {
            VS_IOT_FREE(buf);
            return VS_UPDATE_ERR_FAIL;
        }

        while (offset < file_sz || offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
            vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

            if (0 == memcmp(ptr->manufacture_id, descriptor->manufacture_id, MANUFACTURE_ID_SIZE) &&
                0 == memcmp(ptr->device_type, descriptor->device_type, DEVICE_TYPE_SIZE)) {
                break;
            }

            offset += sizeof(vs_firmware_descriptor_t);
        }
    }

    VS_IOT_FREE(buf);

    return vs_update_write_firmware_descriptor_table_hal(descriptor, sizeof(vs_firmware_descriptor_t));
}

/*************************************************************************/
int
vs_update_load_firmware_descriptor(uint8_t manufacture_id[MANUFACTURE_ID_SIZE],
                                   uint8_t device_type[DEVICE_TYPE_SIZE],
                                   vs_firmware_descriptor_t *descriptor) {

    int res = VS_UPDATE_ERR_NOT_FOUND;
    int file_sz;
    uint8_t *buf = NULL;
    uint32_t offset = 0;

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);

    file_sz = vs_update_get_firmware_descriptor_table_len_hal();

    if (file_sz <= 0) {
        goto terminate;
    }

    uint16_t read_sz;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO(buf, VS_UPDATE_ERR_FAIL);

    if (VS_UPDATE_ERR_OK != vs_update_read_firmware_descriptor_table_hal(buf, file_sz, &read_sz)) {
        res = VS_UPDATE_ERR_FAIL;
        goto terminate;
    }

    while (offset < file_sz || offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
        vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->manufacture_id, manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->device_type, device_type, DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMCPY(descriptor, ptr, sizeof(vs_firmware_descriptor_t));
            res = VS_UPDATE_ERR_OK;
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
vs_update_delete_firmware(vs_firmware_descriptor_t *descriptor) {
    int res = VS_UPDATE_ERR_FAIL;
    int file_sz;
    uint8_t *buf = NULL;

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);

    if (VS_UPDATE_ERR_OK != vs_update_remove_firmware_data_hal(descriptor->manufacture_id, descriptor->device_type)) {
        goto terminate;
    }

    file_sz = vs_update_get_firmware_descriptor_table_len_hal();

    if (file_sz <= 0) {
        goto terminate;
    }

    uint16_t read_sz;
    uint32_t offset = 0;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO(buf, VS_UPDATE_ERR_FAIL);

    if (VS_UPDATE_ERR_OK != vs_update_read_firmware_descriptor_table_hal(buf, file_sz, &read_sz)) {
        goto terminate;
    }

    while (offset < file_sz || offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
        vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->manufacture_id, descriptor->manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->device_type, descriptor->device_type, DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMMOVE(buf + offset,
                           buf + offset + sizeof(vs_firmware_descriptor_t),
                           file_sz - offset - sizeof(vs_firmware_descriptor_t));
            file_sz -= sizeof(vs_firmware_descriptor_t);
            break;
        }
        offset += sizeof(vs_firmware_descriptor_t);
    }

    if (VS_UPDATE_ERR_OK != vs_update_remove_firmware_descriptor_table_hal()) {
        goto terminate;
    }

    if (file_sz) {
        res = vs_update_write_firmware_descriptor_table_hal(buf, file_sz);
    }

terminate:
    VS_IOT_FREE(buf);

    return res;
}