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

#ifndef CLOUD_PARSE_MANIFEST_H
#define CLOUD_PARSE_MANIFEST_H

#include <stdint.h>
#include <stddef.h>
#include <global-hal.h>

#define MANUFACTURE_ID_STR_LEN (32 + 1)
#define DEV_TYPE_ID_STR_LEN (sizeof(uint32_t) + 1)

typedef union {
    uint8_t id[DEVICE_TYPE_SIZE];
    char str[DEV_TYPE_ID_STR_LEN];
} vs_readable_type_t;

typedef struct __attribute__((__packed__)) {
    uint8_t manufacturer_id[MANUFACTURE_ID_STR_LEN];
    vs_readable_type_t device_type;
    char version[16];
    char timestamp[9];
    char fw_file_url[VS_UPD_URL_STR_SIZE];
} vs_firmware_manifest_entry_t;

typedef struct {
    int version;
    int type;
} vs_tl_info_t;

typedef struct {
    vs_tl_info_t info;
    char file_url[VS_UPD_URL_STR_SIZE];
} vs_tl_manifest_entry_t;

#define VS_MANIFEST_FILED "manifest"

#define VS_FW_URL_FIELD "download_url"
#define VS_FW_MANUFACTURER_ID_FIELD "manufacturer_id"
#define VS_FW_DEVICE_TYPE_FIELD "device_type"
#define VS_FW_VERSION_FIELD "version"
#define VS_FW_TIMESTAMP "build_timestamp"
#define VS_FW_PERCENTAGE "percentage"
#define VS_FW_LIST "devices"

#define VS_TL_URL_FIELD "download_url"
#define VS_TL_VERSION_FIELD "version"
#define VS_TL_TYPE_FIELD "type"

int
vs_cloud_is_new_tl_version_available(vs_tl_info_t *tl_info);
int
vs_cloud_is_new_firmware_version_available(const vs_storage_op_ctx_t *fw_storage,
                                           uint8_t manufacture_id[MANUFACTURE_ID_SIZE],
                                           uint8_t device_type[DEVICE_TYPE_SIZE],
                                           vs_firmware_version_t *new_ver);

#endif // CLOUD_PARSE_MANIFEST_H
