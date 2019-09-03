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

#include <virgil/iot/protocols/sdmp/fldt_server.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <global-hal.h>

// TODO : make a set!
static size_t _file_type_mapping_array_size = 0;
static vs_fldt_server_file_type_mapping_t _server_file_type_mapping[10];

static vs_fldt_server_file_type_mapping_t *
vs_fldt_get_mapping_elem(const vs_fldt_file_type_t *file_type) {
    vs_fldt_get_mapping_elem_impl(
            vs_fldt_server_file_type_mapping_t, _server_file_type_mapping, _file_type_mapping_array_size, file_type)
}

/******************************************************************/
int
vs_fldt_GFTI_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    const vs_fldt_gfti_fileinfo_request_t *file_info_request = (const vs_fldt_gfti_fileinfo_request_t *)request;
    const vs_fldt_file_type_t *file_type;
    vs_fldt_server_file_type_mapping_t *file_type_info;
    vs_fldt_gfti_fileinfo_response_t *file_info_response = (vs_fldt_gfti_fileinfo_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(request, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*file_info_request),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gfti_fileinfo_request_t type");

    file_type = &file_info_request->file_type;

    VS_LOG_DEBUG("[FLDT:GFTI] Request for %s", vs_fldt_file_type_descr(file_descr, file_type));

    CHECK_RET(response_buf_sz >= sizeof(*file_info_response),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gfti_fileinfo_response_t structure");

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  get_version,
                  (&file_type_info->storage_context, file_info_request, file_info_response),
                  "Unable to get last file version information for file type %d",
                  file_type->file_type_id);

    VS_LOG_DEBUG("[FLDT:GFTI] Server file information : %s",
                 vs_fldt_file_version_descr(file_descr, &file_info_response->version));

    *response_sz = sizeof(*file_info_response);

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFH_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    const vs_fldt_gnfh_header_request_t *header_request = (const vs_fldt_gnfh_header_request_t *)request;
    const vs_fldt_file_version_t *file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfh_header_response_t *header_response = (vs_fldt_gnfh_header_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(request, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*header_request),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnfh_header_request_t type");

    file_ver = &header_request->version;

    VS_LOG_DEBUG("[FLDT:GNFH] Request for header for file version %s",
                 vs_fldt_file_version_descr(file_descr, file_ver));

    CHECK_RET(response_buf_sz > sizeof(*header_response),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfh_header_response_t structure");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  get_header,
                  (&file_type_info->storage_context, header_request, response_buf_sz, header_response),
                  "Unable to get last file version information for file type %d",
                  file_type->file_type_id);

    *response_sz = sizeof(vs_fldt_gnfh_header_response_t) + header_response->header_size;

    VS_LOG_DEBUG("[FLDT:GNFH] Header : %d bytes data", header_response->header_size);

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFC_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    const vs_fldt_gnfc_chunk_request_t *chunk_request = (const vs_fldt_gnfc_chunk_request_t *)request;
    const vs_fldt_file_version_t *file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfc_chunk_response_t *chunk_response = (vs_fldt_gnfc_chunk_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(request, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*chunk_request),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnfc_chunk_request_t type");

    file_ver = &chunk_request->version;

    VS_LOG_DEBUG("[FLDT:GNFC] Request for chunk %d for file %s",
                 chunk_request->chunk_id,
                 vs_fldt_file_version_descr(file_descr, file_ver));

    CHECK_RET(response_buf_sz > sizeof(*chunk_response),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfc_chunk_response_t structure");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  get_chunk,
                  (&file_type_info->storage_context, chunk_request, response_buf_sz, chunk_response),
                  "Unable to get last file version information for file type %d",
                  file_type->file_type_id);

    *response_sz = sizeof(vs_fldt_gnfc_chunk_response_t) + chunk_response->chunk_size;

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFF_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    const vs_fldt_gnff_footer_request_t *footer_request = (const vs_fldt_gnff_footer_request_t *)request;
    const vs_fldt_file_version_t *file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnff_footer_response_t *footer_response = (vs_fldt_gnff_footer_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(request, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*footer_request),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnff_footer_request_t type");

    file_ver = &footer_request->version;

    VS_LOG_DEBUG("[FLDT:GNFF] Footer request for %s", vs_fldt_file_version_descr(file_descr, file_ver));

    CHECK_RET(response_buf_sz > sizeof(*footer_response),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnff_footer_response_t structure");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    FLDT_CALLBACK(file_type_info,
                  get_footer,
                  (&file_type_info->storage_context, footer_request, response_buf_sz, footer_response),
                  "Unable to get last file version information for file type %d",
                  file_type->file_type_id);

    *response_sz = sizeof(vs_fldt_gnff_footer_response_t) + footer_response->footer_size;

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_update_server_file_type(const vs_fldt_server_file_type_mapping_t *mapping_elem) {
    vs_log_level_t prev_loglev;
    vs_fldt_server_file_type_mapping_t *file_type_mapping = NULL;
    char file_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(mapping_elem, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    VS_LOG_DEBUG("[FLDT] Update file type %s", vs_fldt_file_type_descr(file_descr, &mapping_elem->file_type));

    prev_loglev = vs_logger_get_loglev();
    vs_logger_set_loglev(VS_LOGLEV_ERROR);
    file_type_mapping = vs_fldt_get_mapping_elem(&mapping_elem->file_type);
    vs_logger_set_loglev(prev_loglev);

    if (!file_type_mapping) {
        file_type_mapping = &_server_file_type_mapping[_file_type_mapping_array_size++];
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
vs_fldt_broadcast_new_file(const vs_fldt_infv_new_file_request_t *new_file) {
    char filever_descr[FLDT_FILEVER_BUF];

    VS_LOG_DEBUG("[FLDT] Broadcast new file version present for file %s",
                 vs_fldt_file_version_descr(filever_descr, &new_file->version));

    CHECK_NOT_ZERO_RET(new_file, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                    vs_fldt_broadcast_mac_addr,
                                    VS_FLDT_INFV,
                                    (const uint8_t *)new_file,
                                    sizeof(*new_file)),
              VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"INFV\" broadcast request");

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vd_fldt_init_server(void) {
    vd_fldt_destroy_server();

    vs_fldt_is_gateway = true;

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
void
vd_fldt_destroy_server(void) {
    size_t pos;
    vs_fldt_server_file_type_mapping_t *elem;

    for (pos = 0; pos < _file_type_mapping_array_size; ++pos) {
        elem = &_server_file_type_mapping[pos];

        VS_IOT_ASSERT(elem->destroy && "Destroy function must be specified");

        elem->destroy(&elem->storage_context);
    }

    _file_type_mapping_array_size = 0;
}
