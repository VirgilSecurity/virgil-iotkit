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

#include <virgil/iot/status_code/status_code.h>
#include <private/cloud_include.h>

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
static bool
_hex_str_to_bin(const char *src, uint16_t src_sz, uint8_t *out, uint16_t out_sz) {
    int8_t res[2];
    uint16_t used = 0;

    if (0 == *src) {
        return false;
    }

    if (src_sz % 2) {
        if ((res[0] = _hex_char_to_num(*src)) < 0) {
            return false;
        }
        *(out++) = (uint8_t)res[0];
        src++;
    }

    while (*src && src[1]) {
        if ((res[0] = _hex_char_to_num(*src)) < 0 || (res[1] = _hex_char_to_num(src[1])) < 0) {
            return false;
        }
        *(out++) = ((uint8_t)res[0] << 4) | (uint8_t)res[1];

        src += 2;

        if (++used > out_sz) {
            return false;
        }
    }

    return true;
}

/*************************************************************************/
static bool
_dec_str_to_num8(const char *str, int8_t str_len, uint8_t *num) {
    int8_t i;
    uint8_t deg = 1;
    uint16_t tmp = 0;
    *num = 0;

    if (str_len <= 0 || str_len > 3) {
        return false;
    }

    for (i = str_len - 1; i >= 0; i--) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
        tmp += (uint16_t)(str[i] - 0x30) * deg;
        deg *= 10;
    }

    if (tmp > 255) {
        return false;
    }

    *num = (uint8_t)tmp;
    return true;
}

/*************************************************************************/
static bool
_dec_str_to_num32(const char *str, int8_t str_len, uint32_t *num) {
    int8_t i;
    uint64_t deg = 1;
    uint64_t tmp = 0;
    *num = 0;


    if (str_len <= 0 || str_len > 10) {
        return false;
    }

    for (i = str_len - 1; i >= 0; i--) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
        tmp += (uint64_t)(str[i] - 0x30) * deg;
        deg *= 10;
    }

    if (tmp > 0xFFFFFFFF) {
        return false;
    }

    *num = (uint32_t)tmp;
    return true;
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
static vs_status_e
_parse_version(char *version_str, vs_file_version_t *version) {
    /*parse major*/
    char *ptr = _find_symb_in_str(version_str, '.');

    CHECK_NOT_ZERO_RET(ptr, VS_CODE_ERR_JSON);

    int8_t len = (int8_t)(ptr - version_str);

    CHECK_RET(_dec_str_to_num8(version_str, len, &version->major), VS_CODE_ERR_JSON, "Incorrect version field");
    ptr++;

    /*parse minor*/
    char *ptr1 = _find_symb_in_str(ptr, '.');
    CHECK_NOT_ZERO_RET(ptr1, VS_CODE_ERR_JSON);

    len = (int8_t)(ptr1 - ptr);
    CHECK_RET(_dec_str_to_num8(ptr, len, &version->minor), VS_CODE_ERR_JSON, "Incorrect minor field");
    ptr1++;
    ptr = ptr1;

    /*parse patch*/
    while (ptr1 < version_str + VS_IOT_STRLEN(version_str)) {
        if (*ptr1 < 0x30 || *ptr1 > 0x39) {
            break;
        }
        ptr1++;
    }

    len = (int8_t)(ptr1 - ptr);
    CHECK_RET(_dec_str_to_num8(ptr, len, &version->patch), VS_CODE_ERR_JSON, "Incorrect patch field");
    ptr = ptr1;

    /*parse build*/
    ptr++;
    ptr1 = version_str + VS_IOT_STRLEN(version_str);
    len = (int8_t)(ptr1 - ptr);
    uint32_t build;
    CHECK_RET(_dec_str_to_num32(ptr, len, &build), VS_CODE_ERR_JSON, "Incorrect dev_build field");
    version->build = build;

    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_get_firmware_version_from_manifest(vs_firmware_manifest_entry_t *fm_entry, vs_file_version_t *fw_version) {
    vs_status_e ret_code;
    STATUS_CHECK_RET(_parse_version(fm_entry->version, fw_version), "Error parse file version");

    /*parse build_timestamp*/
    uint32_t timestamp;
    CHECK_RET(_hex_str_to_bin((char *)fm_entry->timestamp,
                              VS_IOT_STRLEN((char *)fm_entry->timestamp),
                              (uint8_t *)&timestamp,
                              sizeof(timestamp)),
              VS_CODE_ERR_JSON,
              "Incorrect timestamp field");

    fw_version->timestamp = VS_IOT_NTOHL(timestamp);

    return VS_CODE_OK;
}

/*************************************************************************/
static bool
_is_member_for_vendor_and_model_present(uint8_t manufacture_id[VS_DEVICE_MANUFACTURE_ID_SIZE],
                                        uint8_t device_type[VS_DEVICE_TYPE_SIZE],
                                        vs_file_version_t *cur_version) {
    vs_firmware_descriptor_t desc;
    int res = vs_firmware_load_firmware_descriptor(manufacture_id, device_type, &desc);

    if (VS_CODE_ERR_NOT_FOUND == res) {
        VS_IOT_MEMSET(cur_version, 0, sizeof(vs_file_version_t));
    } else if (VS_CODE_OK == res) {
        VS_IOT_MEMCPY(cur_version, &desc.info.version, sizeof(vs_file_version_t));
    } else {
        return false;
    }

    return true;
}

/*************************************************************************/
vs_status_e
vs_cloud_is_new_tl_version_available(uint8_t new_tl_type, vs_file_version_t *new_tl_version) {
    vs_tl_header_t tl_header;
    uint8_t buf[VS_TL_STORAGE_MAX_PART_SIZE];
    vs_tl_footer_t *tl_footer = (vs_tl_footer_t *)buf;
    vs_tl_element_info_t info = {.id = VS_TL_ELEMENT_TLH, .index = 0};
    uint16_t res_sz;
    vs_status_e ret_code;

    STATUS_CHECK_RET(vs_tl_load_part(&info, (uint8_t *)&tl_header, sizeof(vs_tl_header_t), &res_sz),
                     "Unable to load Trust List header");

    // Use host endian
    vs_tl_header_to_host(&tl_header, &tl_header);

    info.id = VS_TL_ELEMENT_TLF;
    STATUS_CHECK_RET(vs_tl_load_part(&info, buf, sizeof(buf), &res_sz), "Unable to load Trust List footer");

    if (new_tl_type != tl_footer->tl_type ||
        VS_CODE_OK != vs_update_compare_version(new_tl_version, &tl_header.version)) {
        return VS_CODE_ERR_NOT_FOUND;
    }

    return VS_CODE_OK;
}

/*************************************************************************/
vs_status_e
vs_cloud_is_new_firmware_version_available(vs_firmware_descriptor_t *new_desc) {

    CHECK_NOT_ZERO_RET(new_desc, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Compare the own firmware image version
    if (VS_CODE_OLD_VERSION == vs_firmware_compare_own_version(new_desc)) {
        VS_LOG_WARNING("No need to fetch a new own firmware.");
        return VS_CODE_ERR_NOT_FOUND;
    }

    vs_file_version_t current_ver;

    if (!_is_member_for_vendor_and_model_present(
                new_desc->info.manufacture_id, new_desc->info.device_type, &current_ver) ||
        VS_CODE_OK != vs_update_compare_version(&new_desc->info.version, &current_ver)) {
        return VS_CODE_ERR_NOT_FOUND;
    }
    return VS_CODE_OK;
}

/*************************************************************************/
static vs_status_e
_is_new_fw_version_available_in_manifest(vs_firmware_manifest_entry_t *fm_entry) {
    vs_firmware_descriptor_t new_desc;
    VS_IOT_MEMSET(&new_desc, 0, sizeof(vs_firmware_descriptor_t));

    if (!_hex_str_to_bin((char *)fm_entry->manufacturer_id,
                         VS_IOT_STRLEN((char *)fm_entry->manufacturer_id),
                         new_desc.info.manufacture_id,
                         sizeof(vs_device_manufacture_id_t)) ||
        VS_CODE_OK != _get_firmware_version_from_manifest(fm_entry, &new_desc.info.version)) {
        return VS_CODE_ERR_JSON;
    }
    VS_IOT_MEMCPY(new_desc.info.device_type, fm_entry->device_type.id, sizeof(vs_device_type_t));

    return vs_cloud_is_new_firmware_version_available(&new_desc);
}

/*************************************************************************/
vs_status_e
vs_cloud_parse_firmware_manifest(void *payload, size_t payload_len, char *fw_url) {
    jobj_t jobj;
    vs_firmware_manifest_entry_t fm_entry;
    int url_len;
    int res = VS_CODE_ERR_JSON;

    CHECK_NOT_ZERO_RET(payload, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(fw_url, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_LOG_DEBUG("NEW FIRMWARE: %s", (char *)payload);
    CHECK(VS_JSON_ERR_OK == json_parse_start(&jobj, payload, payload_len), "[FW] Error. Invalid JSON");

    CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_FW_URL_FIELD, &url_len) || url_len <= 0 ||
                  url_len > VS_UPD_URL_STR_SIZE,
          "[FW] Wrong url field length");

    if (VS_JSON_ERR_OK ==
        json_get_val_str(&jobj, VS_FW_URL_FIELD, fm_entry.fw_file_url, sizeof(fm_entry.fw_file_url))) {
        CHECK(VS_JSON_ERR_OK == json_get_composite_object(&jobj, VS_MANIFEST_FILED),
              "[FW] Get composite JSON obj failed");
    } else {
        VS_LOG_ERROR("[FW] Get firmware url failed");
        goto terminate;
    }

    res = VS_CODE_ERR_JSON;

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

        res = _is_new_fw_version_available_in_manifest(&fm_entry);
        if (VS_CODE_OK == res) {
            VS_IOT_STRCPY(fw_url, fm_entry.fw_file_url);
        }
    }

terminate:
    VS_LOG_INFO("[FW] manifest released=%d", json_release_composite_object(&jobj));
    json_parse_stop(&jobj);
    return res;
}

/*************************************************************************/
vs_status_e
vs_cloud_parse_tl_mainfest(void *payload, size_t payload_len, char *tl_url) {
    jobj_t jobj;
    int url_len;
    int res = VS_CODE_ERR_JSON;

    CHECK_NOT_ZERO_RET(payload, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(tl_url, VS_CODE_ERR_NULLPTR_ARGUMENT);

    vs_tl_manifest_entry_t tl_entry;

    VS_LOG_DEBUG("NEW TL: %s", (char *)payload);

    CHECK(VS_JSON_ERR_OK == json_parse_start(&jobj, payload, payload_len), "[TL] Error. Invalid JSON");

    CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_TL_URL_FIELD, &url_len) || url_len <= 0 ||
                  url_len > VS_UPD_URL_STR_SIZE,
          "[TL] Wrong url field length");

    if (VS_JSON_ERR_OK == json_get_val_str(&jobj, VS_TL_URL_FIELD, tl_entry.file_url, sizeof(tl_entry.file_url))) {
        CHECK(VS_JSON_ERR_OK == json_get_composite_object(&jobj, "manifest"), "[TL] Get composite JSON obj failed");
    } else {
        VS_LOG_ERROR("[TL] Get tl url failed");
        goto terminate;
    }

    res = VS_CODE_ERR_CLOUD;

    if (VS_JSON_ERR_OK == json_get_val_int(&jobj, VS_TL_TYPE_FIELD, &tl_entry.info.type) &&
        VS_JSON_ERR_OK ==
                json_get_val_str(&jobj, VS_TL_VERSION_FIELD, tl_entry.info.version, sizeof(tl_entry.info.version))) {
        VS_LOG_INFO("[TL] new tl manifest:");
        VS_LOG_INFO("[TL] url = %s", tl_entry.file_url);
        VS_LOG_INFO("[TL] type = %d", tl_entry.info.type);
        VS_LOG_INFO("[TL] version = %s", tl_entry.info.version);

        vs_status_e ret_code;
        vs_file_version_t new_version;
        STATUS_CHECK_RET(_parse_version(tl_entry.info.version, &new_version), "Error parse file version");

        res = vs_cloud_is_new_tl_version_available(tl_entry.info.type, &new_version);
        if (VS_CODE_OK == res) {
            VS_IOT_STRCPY(tl_url, tl_entry.file_url);
        }
    }

terminate:
    VS_LOG_INFO("[TL] manifest released=%d", json_release_composite_object(&jobj));
    json_parse_stop(&jobj);
    return res;
}
