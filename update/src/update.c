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

#include <trust_list-config.h>
#include <stdlib-config.h>

#include <virgil/iot/update/update.h>
#include <virgil/iot/json/json_parser.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/logger/logger.h>

/*************************************************************************/
static int
_is_new_tl_version_available(vs_tl_manifest_entry_t *tl_entry) {
    vs_tl_header_t tl_header;
    uint8_t tl_footer[VS_TL_STORAGE_MAX_PART_SIZE];
    vs_tl_element_info_t info = {.id = VS_TL_ELEMENT_TLH, .index = 0};
    uint16_t res_sz;

    if (tl_entry->type < 0 || tl_entry->type > 0xFF || (uint32_t)tl_entry->version > 0xFFFF) {
        return VS_UPDATE_ERR_FAIL;
    }

    if (VS_TL_OK != vs_tl_load_part(&info, (uint8_t *)&tl_header, sizeof(vs_tl_header_t), &res_sz)) {
        return VS_UPDATE_ERR_FAIL;
    }

    info.id = VS_TL_ELEMENT_TLF;
    if (VS_TL_OK != vs_tl_load_part(&info, tl_footer, sizeof(tl_footer), &res_sz)) {
        return VS_UPDATE_ERR_FAIL;
    }

    if ((uint8_t)tl_entry->type != ((vs_tl_footer_t *)tl_footer)->tl_type ||
        (uint16_t)tl_entry->version <= tl_header.version) {
        return VS_UPDATE_ERR_FAIL;
    }

    return VS_UPDATE_ERR_OK;
}

/*************************************************************************/
static int
_is_new_fw_version_available(vs_firmware_manifest_entry_t *fm_entry) {

    // TODO: Need to compare both current and new versions of fw
    return VS_UPDATE_ERR_OK;
}

/*************************************************************************/
int
vs_update_parse_firmware_manifest(void *payload, size_t payload_len, char *fw_url) {
    jobj_t jobj;
    vs_firmware_manifest_entry_t fm_entry;

    CHECK_NOT_ZERO(payload, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(fw_url, VS_UPDATE_ERR_INVAL);

    VS_LOG_DEBUG("NEW FIRMWARE: %s", (char *)payload);

    if (VS_JSON_ERR_OK != json_parse_start(&jobj, payload, payload_len)) {
        VS_LOG_ERROR("[FW] Error. Invalid JSON");
        return VS_UPDATE_ERR_FAIL;
    }

    if (VS_JSON_ERR_OK ==
        json_get_val_str(&jobj, VS_FW_URL_FIELD, fm_entry.fw_file_url, sizeof(fm_entry.fw_file_url))) {
        if (json_get_composite_object(&jobj, VS_MANIFEST_FILED)) {
            VS_LOG_ERROR("[FW] Get composite JSON obj failed");
            return VS_UPDATE_ERR_FAIL;
        }
    } else {
        VS_LOG_ERROR("[FW] Get firmware url failed");
        return VS_UPDATE_ERR_FAIL;
    }

    int res = VS_UPDATE_ERR_FAIL;

    if (VS_JSON_ERR_OK ==
                json_get_val_str(&jobj, VS_FW_MANUFACTURER_ID_FIELD, fm_entry.manufID.str, sizeof(fm_entry.manufID)) &&
        VS_JSON_ERR_OK ==
                json_get_val_str(&jobj, VS_FW_MODEL_TYPE_FIELD, fm_entry.modelID.str, sizeof(fm_entry.modelID)) &&
        VS_JSON_ERR_OK ==
                json_get_val_str(
                        &jobj, VS_FW_VERSION_FIELD, fm_entry.firmwareVersion, sizeof(fm_entry.firmwareVersion)) &&
        VS_JSON_ERR_OK == json_get_val_str(&jobj, VS_FW_TIMESTAMP, fm_entry.timestamp, sizeof(fm_entry.timestamp))) {
        VS_LOG_INFO("[FW] new firmware manifest:");
        VS_LOG_INFO("[FW] url = %s", fm_entry.fw_file_url);
        VS_LOG_INFO("[FW] manufacture_id = %s", fm_entry.manufID.str);
        VS_LOG_INFO("[FW] model_id = %s", fm_entry.modelID.str);
        VS_LOG_INFO("[FW] version = %s", fm_entry.firmwareVersion);
        VS_LOG_INFO("[FW] timestamp = %s", fm_entry.timestamp);

        res = _is_new_fw_version_available(&fm_entry);
        if (VS_UPDATE_ERR_OK == res) {
            VS_IOT_STRCPY(fw_url, fm_entry.fw_file_url);
        }
    }

    return res;
}

/*************************************************************************/
int
vs_update_parse_tl_mainfest(void *payload, size_t payload_len, char *tl_url) {
    jobj_t jobj;

    CHECK_NOT_ZERO(payload, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(tl_url, VS_UPDATE_ERR_INVAL);

    vs_tl_manifest_entry_t tl_entry;

    VS_LOG_DEBUG("NEW TL: %s", (char *)payload);

    if (VS_JSON_ERR_OK != json_parse_start(&jobj, payload, payload_len)) {
        VS_LOG_ERROR("[TL] Error. Invalid JSON");
        return VS_UPDATE_ERR_FAIL;
    }

    if (VS_JSON_ERR_OK == json_get_val_str(&jobj, VS_TL_URL_FIELD, tl_entry.file_url, sizeof(tl_entry.file_url))) {
        if (json_get_composite_object(&jobj, "manifest")) {
            VS_LOG_ERROR("[TL] Get composite JSON obj failed");
            return VS_UPDATE_ERR_FAIL;
        }
    } else {
        VS_LOG_ERROR("[TL] Get tl url failed");
        return VS_UPDATE_ERR_FAIL;
    }

    int res = VS_UPDATE_ERR_FAIL;

    if (VS_JSON_ERR_OK == json_get_val_int(&jobj, VS_TL_TYPE_FIELD, &tl_entry.type) &&
        VS_JSON_ERR_OK == json_get_val_int(&jobj, VS_TL_VERSION_FIELD, &tl_entry.version)) {
        VS_LOG_INFO("[TL] new tl manifest:");
        VS_LOG_INFO("[TL] url = %s", tl_entry.file_url);
        VS_LOG_INFO("[TL] type = %d", tl_entry.type);
        VS_LOG_INFO("[TL] version = %d", tl_entry.version);

        res = _is_new_tl_version_available(&tl_entry);
        if (VS_UPDATE_ERR_OK == res) {
            VS_IOT_STRCPY(tl_url, tl_entry.file_url);
        }
    }

    int released = json_release_composite_object(&jobj);
    VS_LOG_INFO("[TL] manifest released=%d", released);
    json_parse_stop(&jobj);
    return res;
}
