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

#ifndef VS_UPDATE_H
#define VS_UPDATE_H

#include <global-hal.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>

#define FILE_TYPE_ADD_INFO_SZ (64) // vs_update_file_type_t.add_info field size
#define FILE_VERSION_INFO_SZ (64) // vs_update_file_version_t.version field size

#define UPDATE_CHECK(OPERATION, MESSAGE, ...)                                                                            \
    CHECK_RET((ret_code = (OPERATION)) == VS_CODE_OK, ret_code, MESSAGE, ##__VA_ARGS__)

enum vs_update_file_type_id_t {VS_UPDATE_FIRMWARE, VS_UPDATE_TRUST_LIST, USER = 256};

typedef struct __attribute__((__packed__)) {
    uint16_t file_type_id;
    uint8_t add_info[FILE_TYPE_ADD_INFO_SZ];
} vs_update_file_type_t;

typedef struct __attribute__((__packed__)) {
    uint8_t version[FILE_VERSION_INFO_SZ];
} vs_update_file_version_t;

struct vs_update_interface_t;

char *
vs_update_type_descr(vs_update_file_type_t *file_type, const struct vs_update_interface_t *update_context, char *buf, size_t buf_size);

bool
vs_update_equal_file_type(struct vs_update_interface_t *update_context, vs_update_file_type_t *file_type, const vs_update_file_type_t *unknown_file_type);

typedef vs_status_code_e (*vs_update_get_version_cb_t)(void *context, vs_update_file_type_t *file_type, vs_update_file_version_t *file_version);
typedef vs_status_code_e (*vs_update_get_header_size_cb_t)(void *context, vs_update_file_type_t *file_type, size_t *header_size);
typedef vs_status_code_e (*vs_update_get_file_size_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, size_t *file_size);
typedef vs_status_code_e (*vs_update_has_footer_cb_t)(void *context, vs_update_file_type_t *file_type, bool *has_footer);
typedef vs_status_code_e (*vs_update_inc_data_offset_cb_t)(void *context, vs_update_file_type_t *file_type, size_t current_offset, size_t loaded_data_size, size_t *next_offset);
typedef bool (*vs_update_equal_file_type_cb_t)(void *context, vs_update_file_type_t *file_type, const vs_update_file_type_t *unknown_file_type);

typedef vs_status_code_e (*vs_update_get_header_cb_t)(void *context, vs_update_file_type_t *file_type, void *header_buffer, size_t buffer_size, size_t *header_size);
typedef vs_status_code_e (*vs_update_get_data_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, void *data_buffer, size_t buffer_size, size_t *data_size, size_t data_offset);
typedef vs_status_code_e (*vs_update_get_footer_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, void *footer_buffer, size_t buffer_size, size_t *footer_size);

typedef vs_status_code_e (*vs_update_set_header_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, size_t header_size, size_t *file_size);
typedef vs_status_code_e (*vs_update_set_data_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, const void *file_data, size_t data_size, size_t data_offset);
typedef vs_status_code_e (*vs_update_set_footer_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, const void *file_footer, size_t footer_size);

typedef bool (*vs_update_file_is_newer_cb_t)(void *context, vs_update_file_type_t *file_type, const vs_update_file_version_t *available_file, const vs_update_file_version_t *new_file);
typedef void (*vs_update_free_item_cb_t)(void *context, vs_update_file_type_t *file_type);

typedef char* (*vs_update_describe_type_cb_t)(void *context, vs_update_file_type_t *file_type, char *buffer, size_t buf_size);
typedef char* (*vs_update_describe_version_cb_t)(void *context, vs_update_file_type_t *file_type, const vs_update_file_version_t *version, char *buffer, size_t buf_size, bool add_filetype_description);

typedef struct __attribute__((__packed__)) vs_update_interface_t {
    vs_update_get_version_cb_t        get_version;
    vs_update_get_header_size_cb_t    get_header_size;
    vs_update_get_file_size_cb_t      get_file_size;
    vs_update_has_footer_cb_t         has_footer;
    vs_update_inc_data_offset_cb_t    inc_data_offset;
    vs_update_equal_file_type_cb_t    equal_file_type;

    vs_update_get_header_cb_t         get_header;
    vs_update_get_data_cb_t           get_data;
    vs_update_get_footer_cb_t         get_footer;

    vs_update_set_header_cb_t         set_header;
    vs_update_set_data_cb_t           set_data;
    vs_update_set_footer_cb_t         set_footer;

    vs_update_free_item_cb_t          free_item;

    vs_update_file_is_newer_cb_t      file_is_newer;
    vs_update_describe_type_cb_t      describe_type;
    vs_update_describe_version_cb_t   describe_version;

    void *file_context;

} vs_update_interface_t;

#endif // VS_UPDATE_H
