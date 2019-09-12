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

#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_private.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include <global-hal.h>

// TODO : make a set!
static size_t _file_type_mapping_array_size = 0;
static vs_fldt_client_file_type_mapping_t _client_file_type_mapping[10];

static vs_fldt_client_file_type_mapping_t *
vs_fldt_get_mapping_elem(const vs_fldt_file_type_t *file_type) {
    vs_fldt_get_mapping_elem_impl(
            vs_fldt_client_file_type_mapping_t, _client_file_type_mapping, _file_type_mapping_array_size, file_type)
}

/******************************************************************/
static int
_check_download_need(const char *opcode,
                     vs_fldt_client_file_type_mapping_t *file_type_info,
                     const vs_fldt_file_version_t *new_file_ver,
                     bool *download) {
    const vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_file_version_t present_file_ver;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(new_file_ver, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    file_type = &new_file_ver->file_type;

    FLDT_CALLBACK(file_type_info,
                  get_current_version,
                  (&file_type_info->storage_context, file_type, &present_file_ver),
                  "Unable to retrieve present file version for file type %d",
                  file_type->file_type_id);


    VS_LOG_DEBUG(
            "[FLDT:%s] Present file version : %s", opcode, vs_fldt_file_version_descr(file_descr, &present_file_ver));

    VS_LOG_DEBUG("[FLDT:%s] New file version : %s", opcode, vs_fldt_file_version_descr(file_descr, new_file_ver));

    *download = vs_fldt_file_is_newer(new_file_ver, &present_file_ver);

    if (*download) {
        VS_LOG_DEBUG("[FLDT:%s] Need to download new version", opcode);
    } else {
        VS_LOG_DEBUG("[FLDT:%s] No need to download new version", opcode);
    }

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_INFV_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    const vs_fldt_infv_new_file_request_t *new_file = (const vs_fldt_infv_new_file_request_t *)request;
    const vs_fldt_file_version_t *new_file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    bool download;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(request, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_buf_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*new_file),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Unsupported request structure, vs_fldt_infv_new_file_request_t has been waited");

    new_file_ver = &new_file->version;

    VS_LOG_DEBUG("[FLDT:INFV] Request for new file : %s", vs_fldt_file_version_descr(file_descr, new_file_ver));

    file_type = &new_file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  set_gateway_mac,
                  (&new_file->gateway_mac),
                  "Unable to save MAC address",
                  file_type->file_type_id);

    FLDT_CHECK(_check_download_need("INFV", file_type_info, new_file_ver, &download), "Unable to check download need");

    if (download) {

        FLDT_CALLBACK(file_type_info,
                      update_file,
                      (&file_type_info->storage_context, new_file),
                      "Unable to notify new file version for file type %d",
                      file_type->file_type_id);
    }

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GFTI_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_infv_new_file_request_t new_file;
    vs_fldt_gfti_fileinfo_response_t *file_info = (vs_fldt_gfti_fileinfo_response_t *)response;
    vs_fldt_file_version_t *file_ver = NULL;
    vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    bool download;
    vs_fldt_ret_code_e fldt_ret_code;

    (void)is_ack;

    file_ver = &file_info->version;

    VS_LOG_DEBUG("[FLDT:GFTI] Response for file : %s", vs_fldt_file_version_descr(file_descr, file_ver));

    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(response_sz == sizeof(*file_info),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gfti_fileinfo_response_t type");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  got_info,
                  (&file_type_info->storage_context, file_info),
                  "Unable to process received file information for file : %s",
                  vs_fldt_file_version_descr(file_descr, file_ver));

    FLDT_CHECK(_check_download_need("GFTI", file_type_info, file_ver, &download), "Unable to check download need");

    if (download) {

        FLDT_CALLBACK(file_type_info,
                      set_gateway_mac,
                      (&file_info->gateway_mac),
                      "Unable to save MAC address",
                      file_type->file_type_id);

        VS_IOT_MEMCPY(&new_file.gateway_mac, &file_info->gateway_mac, sizeof(new_file.gateway_mac));
        VS_IOT_MEMCPY(&new_file.version, file_ver, sizeof(*file_ver));

        FLDT_CALLBACK(file_type_info,
                      update_file,
                      (&file_type_info->storage_context, &new_file),
                      "Unable to notify new file version for file type %d",
                      file_type->file_type_id);
    }

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFH_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfh_header_response_t *header = (vs_fldt_gnfh_header_response_t *)response;
    vs_fldt_file_version_t *file_ver = NULL;
    vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    (void)is_ack;

    file_ver = &header->version;

    VS_LOG_DEBUG("[FLDT:GNFH] Response for file : %s. File size %d bytes, %s",
                 vs_fldt_file_version_descr(file_descr, file_ver),
                 header->file_size,
                 header->has_footer ? "has footer" : "no footer");

    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(response_sz >= sizeof(*header),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnfh_header_response_t type");

    file_type = &file_ver->file_type;
    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  got_header,
                  (&file_type_info->storage_context, header),
                  "Unable to process received file information for file : %s",
                  vs_fldt_file_version_descr(file_descr, file_ver));

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFD_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfd_data_response_t *data = (vs_fldt_gnfd_data_response_t *)response;
    vs_fldt_file_version_t *file_ver = NULL;
    vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    (void)is_ack;

    file_ver = &data->version;

    VS_LOG_DEBUG("[FLDT:GNFD] Response for file : %s. Data offset %d, size %d",
                 vs_fldt_file_version_descr(file_descr, file_ver),
                 data->offset,
                 (int)data->data_size);

    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(response_sz >= sizeof(*data) && (response_sz == sizeof(*data) + data->data_size),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnfd_data_response_t type");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  got_data,
                  (&file_type_info->storage_context, data),
                  "Unable to process received file information for file : %s",
                  vs_fldt_file_version_descr(file_descr, file_ver));

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFF_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnff_footer_response_t *footer = (vs_fldt_gnff_footer_response_t *)response;
    vs_fldt_file_version_t *file_ver = NULL;
    vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    (void)is_ack;

    file_ver = &footer->version;

    VS_LOG_DEBUG("[FLDT:GNFF] Response for file : %s. Footer size %d bytes",
                 vs_fldt_file_version_descr(file_descr, file_ver),
                 footer->footer_size);

    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(response_sz >= sizeof(*footer) && (response_sz == sizeof(*footer) + footer->footer_size),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnff_footer_response_t type");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  got_footer,
                  (&file_type_info->storage_context, footer),
                  "Unable to process received file information for file : %s",
                  vs_fldt_file_version_descr(file_descr, file_ver));

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_update_client_file_type(const vs_fldt_client_file_type_mapping_t *mapping_elem) {
    vs_log_level_t prev_loglev;
    vs_fldt_client_file_type_mapping_t *file_type_mapping = NULL;
    char file_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(mapping_elem, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    VS_LOG_DEBUG("[FLDT] Update file type %s", vs_fldt_file_type_descr(file_descr, &mapping_elem->file_type));

    prev_loglev = vs_logger_get_loglev();
    vs_logger_set_loglev(VS_LOGLEV_ERROR);
    file_type_mapping = vs_fldt_get_mapping_elem(&mapping_elem->file_type);
    vs_logger_set_loglev(prev_loglev);

    if (!file_type_mapping) {
        file_type_mapping = &_client_file_type_mapping[_file_type_mapping_array_size++];
        VS_LOG_DEBUG("[FLDT] File type is not found, add new entry. Array size = %d", _file_type_mapping_array_size);
    } else {
        VS_IOT_ASSERT(file_type_mapping->destroy && "Destroy function must be specified");
        file_type_mapping->destroy(&file_type_mapping->storage_context);
        VS_LOG_DEBUG("[FLDT] File type is already present, update");
    }

    VS_IOT_MEMCPY(file_type_mapping, mapping_elem, sizeof(*mapping_elem));

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_ask_file_type_info(const vs_fldt_gfti_fileinfo_request_t *file_type) {
    char file_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(file_type, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    VS_LOG_DEBUG("[FLDT] Ask file type information for file type %s",
                 vs_fldt_file_type_descr(file_descr, &file_type->file_type));

    CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                    vs_fldt_broadcast_mac_addr,
                                    VS_FLDT_GFTI,
                                    (const uint8_t *)file_type,
                                    sizeof(*file_type)),
              VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"GFTI\" server request");

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_ask_file_header(const vs_mac_addr_t *mac, const vs_fldt_gnfh_header_request_t *header_request) {
    char file_descr[FLDT_FILEVER_BUF];

    VS_LOG_DEBUG("[FLDT] Ask file header for file : %s",
                 vs_fldt_file_version_descr(file_descr, &header_request->version));

    CHECK_NOT_ZERO_RET(mac, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(header_request, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(!vs_fldt_send_request(
                      vs_fldt_netif, mac, VS_FLDT_GNFH, (const uint8_t *)header_request, sizeof(*header_request)),
              VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"GNFH\" server request");

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_ask_file_data(const vs_mac_addr_t *mac, vs_fldt_gnfd_data_request_t *file_data) {
    char file_descr[FLDT_FILEVER_BUF];

    VS_LOG_DEBUG("[FLDT] Ask file data offset %d for file : %s",
                 file_data->offset,
                 vs_fldt_file_version_descr(file_descr, &file_data->version));

    CHECK_NOT_ZERO_RET(mac, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_data, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(!vs_fldt_send_request(vs_fldt_netif, mac, VS_FLDT_GNFD, (const uint8_t *)file_data, sizeof(*file_data)),
              VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"GNFD\" server request");

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_ask_file_footer(const vs_mac_addr_t *mac, const vs_fldt_gnff_footer_request_t *file_footer) {
    char file_descr[FLDT_FILEVER_BUF];

    VS_LOG_DEBUG("[FLDT] Ask file footer for file : %s", vs_fldt_file_version_descr(file_descr, &file_footer->version));

    CHECK_NOT_ZERO_RET(mac, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_footer, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(
            !vs_fldt_send_request(vs_fldt_netif, mac, VS_FLDT_GNFF, (const uint8_t *)file_footer, sizeof(*file_footer)),
            VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
            "Unable to send FLDT \"GNFF\" server request");

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_init_client(void) {
    vs_fldt_destroy_client();

    vs_fldt_is_gateway = false;

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
void
vs_fldt_destroy_client(void) {
    size_t pos;
    vs_fldt_client_file_type_mapping_t *elem;

    for (pos = 0; pos < _file_type_mapping_array_size; ++pos) {
        elem = &_client_file_type_mapping[pos];

        VS_IOT_ASSERT(elem->destroy && "Destroy function must be specified");

        elem->destroy(&elem->storage_context);
    }

    _file_type_mapping_array_size = 0;
}