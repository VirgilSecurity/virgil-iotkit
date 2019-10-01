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

#include <virgil/iot/cloud/private/cloud_include.h>
#include <virgil/iot/trust_list/private/tl_operations.h>

/*************************************************************************/
int
vs_cloud_is_new_tl_version_available(vs_tl_info_t *tl_info) {
    vs_tl_header_t tl_header;
    uint8_t tl_footer[VS_TL_STORAGE_MAX_PART_SIZE];
    vs_tl_element_info_t info = {.id = VS_TL_ELEMENT_TLH, .index = 0};
    uint16_t res_sz;

    if (tl_info->type < 0 || tl_info->type > 0xFF || (uint32_t)tl_info->version > 0xFFFF) {
        return VS_CLOUD_ERR_INVAL;
    }

    if (VS_STORAGE_OK != vs_tl_load_part(&info, (uint8_t *)&tl_header, sizeof(vs_tl_header_t), &res_sz)) {
        return VS_CLOUD_ERR_FAIL;
    }

    // Use host endian
    vs_tl_header_to_host(&tl_header, &tl_header);

    info.id = VS_TL_ELEMENT_TLF;
    if (VS_STORAGE_OK != vs_tl_load_part(&info, tl_footer, sizeof(tl_footer), &res_sz)) {
        return VS_CLOUD_ERR_FAIL;
    }

    if ((uint8_t)tl_info->type != ((vs_tl_footer_t *)tl_footer)->tl_type ||
        (uint16_t)tl_info->version <= tl_header.version) {
        return VS_CLOUD_ERR_NOT_FOUND;
    }

    return VS_CLOUD_ERR_OK;
}

/*************************************************************************/
static int8_t
_hex_char_to_num(char input) {
    if (input >= '0' && input <= '9') {
        return input - '0';
    }

    if (input >= 'A' && input <= 'F') {
        return input - 'A' + 10;
    }

    if (input >= 'a' && input <= 'f') {
        return input - 'a' + 10;
    }

    return -1;
}

/*************************************************************************/
static int
_hex_str_to_bin(const char *src, uint8_t *out, uint16_t out_sz) {
    int8_t res[2];
    uint16_t used = 0;

    while (*src && src[1]) {
        if ((res[0] = _hex_char_to_num(*src)) < 0 || (res[1] = _hex_char_to_num(src[1])) < 0) {
            return -1;
        }
        *(out++) = ((uint8_t)res[0] << 4) | (uint8_t)res[1];

        src += 2;

        if (++used > out_sz) {
            return -1;
        }
    }
    return 0;
}

/*************************************************************************/
static int
_dec_str_to_bin(const char *str, int8_t str_len, uint8_t *num) {
    int8_t i;
    uint8_t deg = 1;
    uint16_t tmp = 0;
    *num = 0;

    if (str_len <= 0 || str_len > 3) {
        return -1;
    }

    for (i = str_len - 1; i >= 0; i--) {
        if (str[i] < '0' || str[i] > '9') {
            return -1;
        }
        tmp += (uint16_t)(str[i] - 0x30) * deg;
        deg *= 10;
    }

    if (tmp > 255) {
        return -1;
    }

    *num = (uint8_t)tmp;
    return 0;
}

/*************************************************************************/
static char *
_find_symb_in_str(char *str, char symb) {
    char *ptr = NULL;

    while (*str) {
        if (*str == symb) {
            ptr = str;
            break;
        }
        ++str;
    }
    return ptr;
}

/*************************************************************************/
static int
_get_firmware_version_from_manifest(vs_firmware_manifest_entry_t *fm_entry, vs_firmware_version_t *fw_version) {
    /*parse major*/
    char *ptr = _find_symb_in_str(fm_entry->version, '.');
    if (NULL == ptr) {
        return VS_CLOUD_ERR_FAIL;
    }

    int8_t len = (int8_t)(ptr - fm_entry->version);
    if (0 != _dec_str_to_bin(fm_entry->version, len, &fw_version->major)) {
        return VS_CLOUD_ERR_FAIL;
    }
    ptr++;

    /*parse minor*/
    char *ptr1 = _find_symb_in_str(ptr, '.');
    if (NULL == ptr1) {
        return VS_CLOUD_ERR_FAIL;
    }

    len = (int8_t)(ptr1 - ptr);
    if (0 != _dec_str_to_bin(ptr, len, &fw_version->minor)) {
        return VS_CLOUD_ERR_FAIL;
    }
    ptr1++;
    ptr = ptr1;

    /*parse patch*/
    while (ptr1 < fm_entry->version + VS_IOT_STRLEN(fm_entry->version)) {
        if (*ptr1 < 0x30 || *ptr1 > 0x39) {
            break;
        }
        ptr1++;
    }

    len = (int8_t)(ptr1 - ptr);
    if (0 != _dec_str_to_bin(ptr, len, &fw_version->patch)) {
        return VS_CLOUD_ERR_FAIL;
    }
    ptr = ptr1;

    /*parse dev_milestone*/
    fw_version->dev_milestone = *ptr;

    /*parse dev_build*/
    ptr++;
    ptr1 = fm_entry->version + VS_IOT_STRLEN(fm_entry->version);
    len = (int8_t)(ptr1 - ptr);
    if (0 != _dec_str_to_bin(ptr, len, &fw_version->dev_build)) {
        return VS_CLOUD_ERR_FAIL;
    }

    /*parse build_timestamp*/
    uint8_t timestamp[sizeof(uint32_t)];
    if (_hex_str_to_bin((char *)fm_entry->timestamp, timestamp, sizeof(timestamp)) < 0) {
        return VS_CLOUD_ERR_FAIL;
    }

    fw_version->timestamp = VS_IOT_NTOHL(*(uint32_t *)timestamp); //-V1032 (PVS_IGNORE)

    return VS_CLOUD_ERR_OK;
}

/*************************************************************************/
static bool
_is_member_for_vendor_and_model_present(const vs_storage_op_ctx_t *fw_storage,
                                        uint8_t manufacture_id[MANUFACTURE_ID_SIZE],
                                        uint8_t device_type[DEVICE_TYPE_SIZE],
                                        vs_firmware_version_t *cur_version) {
    // TODO: Need to arrange models table with current version of devices
    vs_firmware_descriptor_t desc;
    int res = vs_firmware_load_firmware_descriptor(fw_storage, manufacture_id, device_type, &desc);

    if (VS_STORAGE_ERROR_NOT_FOUND == res) {
        VS_IOT_MEMSET(cur_version, 0, sizeof(vs_firmware_version_t));
    } else if (VS_STORAGE_OK == res) {
        VS_IOT_MEMCPY(cur_version, &desc.info.version, sizeof(vs_firmware_version_t));
    } else {
        return false;
    }

    return true;
}

/*************************************************************************/
int
vs_cloud_is_new_firmware_version_available(const vs_storage_op_ctx_t *fw_storage,
                                           uint8_t manufacture_id[MANUFACTURE_ID_SIZE],
                                           uint8_t device_type[DEVICE_TYPE_SIZE],
                                           vs_firmware_version_t *new_ver) {
    vs_firmware_version_t current_ver;

    if (!_is_member_for_vendor_and_model_present(fw_storage, manufacture_id, device_type, &current_ver) ||
        0 <= VS_IOT_MEMCMP(&(current_ver.major),&(new_ver->major),    //-V512 (PVS_IGNORE)
                                            sizeof(vs_firmware_version_t) - sizeof(current_ver.app_type))) {
        return VS_CLOUD_ERR_NOT_FOUND;
    }
    return VS_CLOUD_ERR_OK;
}

/*************************************************************************/
static int
_is_new_fw_version_available_in_manifest(const vs_storage_op_ctx_t *fw_storage,
                                         vs_firmware_manifest_entry_t *fm_entry) {
    vs_firmware_version_t new_ver;
    uint8_t manufacture_id[MANUFACTURE_ID_SIZE];

    if (_hex_str_to_bin((char *)fm_entry->manufacturer_id, manufacture_id, sizeof(manufacture_id)) < 0 ||
        VS_CLOUD_ERR_OK != _get_firmware_version_from_manifest(fm_entry, &new_ver)) {
        return VS_CLOUD_ERR_FAIL;
    }

    return vs_cloud_is_new_firmware_version_available(fw_storage, manufacture_id, fm_entry->device_type.id, &new_ver);
}

/*************************************************************************/
int
vs_cloud_parse_firmware_manifest(const vs_storage_op_ctx_t *fw_storage,
                                 void *payload,
                                 size_t payload_len,
                                 char *fw_url) {
    jobj_t jobj;
    vs_firmware_manifest_entry_t fm_entry;

    CHECK_NOT_ZERO_RET(payload, VS_CLOUD_ERR_INVAL);
    CHECK_NOT_ZERO_RET(fw_url, VS_CLOUD_ERR_INVAL);

    VS_LOG_DEBUG("NEW FIRMWARE: %s", (char *)payload);

    if (VS_JSON_ERR_OK != json_parse_start(&jobj, payload, payload_len)) {
        VS_LOG_ERROR("[FW] Error. Invalid JSON");
        return VS_CLOUD_ERR_FAIL;
    }

    if (VS_JSON_ERR_OK ==
        json_get_val_str(&jobj, VS_FW_URL_FIELD, fm_entry.fw_file_url, sizeof(fm_entry.fw_file_url))) {
        if (json_get_composite_object(&jobj, VS_MANIFEST_FILED)) {
            VS_LOG_ERROR("[FW] Get composite JSON obj failed");
            return VS_CLOUD_ERR_FAIL;
        }
    } else {
        VS_LOG_ERROR("[FW] Get firmware url failed");
        return VS_CLOUD_ERR_FAIL;
    }

    int res = VS_CLOUD_ERR_FAIL;

    if (VS_JSON_ERR_OK == json_get_val_str(&jobj,
                                           VS_FW_MANUFACTURER_ID_FIELD,
                                           (char *)fm_entry.manufacturer_id,
                                           sizeof(fm_entry.manufacturer_id)) &&
        VS_JSON_ERR_OK ==
                json_get_val_str(
                        &jobj, VS_FW_DEVICE_TYPE_FIELD, fm_entry.device_type.str, sizeof(fm_entry.device_type)) &&
        VS_JSON_ERR_OK == json_get_val_str(&jobj, VS_FW_VERSION_FIELD, fm_entry.version, sizeof(fm_entry.version)) &&
        VS_JSON_ERR_OK == json_get_val_str(&jobj, VS_FW_TIMESTAMP, fm_entry.timestamp, sizeof(fm_entry.timestamp))) {
        VS_LOG_INFO("[FW] new firmware manifest:");
        VS_LOG_INFO("[FW] url = %s", fm_entry.fw_file_url);
        VS_LOG_INFO("[FW] manufacture_id = %s", fm_entry.manufacturer_id);
        VS_LOG_INFO("[FW] device_type = %s", fm_entry.device_type.str);
        VS_LOG_INFO("[FW] version = %s", fm_entry.version);
        VS_LOG_INFO("[FW] timestamp = %s", fm_entry.timestamp);

        res = _is_new_fw_version_available_in_manifest(fw_storage, &fm_entry);
        if (VS_CLOUD_ERR_OK == res) {
            VS_IOT_STRCPY(fw_url, fm_entry.fw_file_url);
        }
    }

    return res;
}

/*************************************************************************/
int
vs_cloud_parse_tl_mainfest(void *payload, size_t payload_len, char *tl_url) {
    jobj_t jobj;

    CHECK_NOT_ZERO_RET(payload, VS_CLOUD_ERR_INVAL);
    CHECK_NOT_ZERO_RET(tl_url, VS_CLOUD_ERR_INVAL);

    vs_tl_manifest_entry_t tl_entry;

    VS_LOG_DEBUG("NEW TL: %s", (char *)payload);

    if (VS_JSON_ERR_OK != json_parse_start(&jobj, payload, payload_len)) {
        VS_LOG_ERROR("[TL] Error. Invalid JSON");
        return VS_CLOUD_ERR_FAIL;
    }

    if (VS_JSON_ERR_OK == json_get_val_str(&jobj, VS_TL_URL_FIELD, tl_entry.file_url, sizeof(tl_entry.file_url))) {
        if (json_get_composite_object(&jobj, "manifest")) {
            VS_LOG_ERROR("[TL] Get composite JSON obj failed");
            return VS_CLOUD_ERR_FAIL;
        }
    } else {
        VS_LOG_ERROR("[TL] Get tl url failed");
        return VS_CLOUD_ERR_FAIL;
    }

    int res = VS_CLOUD_ERR_FAIL;

    if (VS_JSON_ERR_OK == json_get_val_int(&jobj, VS_TL_TYPE_FIELD, &tl_entry.info.type) &&
        VS_JSON_ERR_OK == json_get_val_int(&jobj, VS_TL_VERSION_FIELD, &tl_entry.info.version)) {
        VS_LOG_INFO("[TL] new tl manifest:");
        VS_LOG_INFO("[TL] url = %s", tl_entry.file_url);
        VS_LOG_INFO("[TL] type = %d", tl_entry.info.type);
        VS_LOG_INFO("[TL] version = %d", tl_entry.info.version);

        res = vs_cloud_is_new_tl_version_available(&tl_entry.info);
        if (VS_CLOUD_ERR_OK == res) {
            VS_IOT_STRCPY(tl_url, tl_entry.file_url);
        }
    }

    int released = json_release_composite_object(&jobj);
    VS_LOG_INFO("[TL] manifest released=%d", released);
    json_parse_stop(&jobj);
    return res;
}
