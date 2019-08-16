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

static vs_fldt_server_file_type_mapping_t _server_file_type_mapping[FLDT_SERVER_FILE_MAPPING_SZ];
static size_t _server_file_type_mapping_sz = 0;

/******************************************************************/
static int
_find_file_type(const vs_fldt_file_type_t *file_type) {
    vs_fldt_find_file_type_impl(file_type, _server_file_type_mapping, _server_file_type_mapping_sz);
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
    const vs_fldt_server_file_type_mapping_t *file_type_info;
    vs_fldt_gfti_fileinfo_response_t *file_info_response = (vs_fldt_gfti_fileinfo_response_t *)response;
    char file_ver_descr[FLDT_FILEVER_BUF];
    size_t id;

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(request_sz, -2);
    CHECK_NOT_ZERO_RET(response, -3);
    CHECK_NOT_ZERO_RET(response_sz, -4);

    CHECK_RET(request_sz == sizeof(*file_info_request),
              -5,
              "Request buffer must be of vs_fldt_gfti_fileinfo_request_t type");

    CHECK_RET(response_buf_sz >= sizeof(*file_info_response),
              -6,
              "Response buffer must have enough size to store vs_fldt_gfti_fileinfo_response_t structure");

    file_type = &file_info_request->file_type;

    if (NO_FILE_TYPE == (id = _find_file_type(file_type))) {
        VS_LOG_WARNING("File type %s has not been added to the file type mapping", vs_fldt_file_type_descr(file_type));
        return -7;
    }

    VS_LOG_DEBUG("[FLDT:GFTI] request for file type \"%s\"", vs_fldt_file_type_descr(file_type));

    file_type_info = _server_file_type_mapping + id;

    CHECK_RET(file_type_info->get_version,
              -8,
              "There is no get_version callback for file type \"%s\"",
              vs_fldt_file_type_descr(file_type));

    CHECK_RET(!file_type_info->get_version(file_info_request, file_info_response),
              -9,
              "Unable to get last file version information for file type \"%s\"",
              vs_fldt_file_type_descr(file_type));

    VS_LOG_DEBUG("[FLDT:GFTI] server file information : %s",
                 vs_fldt_file_version_descr(file_ver_descr, &file_info_response->version));

    *response_sz = sizeof(vs_fldt_file_version_t);

    return 0;
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
    const vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfh_header_response_t *header_response = (vs_fldt_gnfh_header_response_t *)response;
    char file_ver_descr[FLDT_FILEVER_BUF];
    size_t id;

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(request_sz, -2);
    CHECK_NOT_ZERO_RET(response, -3);
    CHECK_NOT_ZERO_RET(response_sz, -4);

    CHECK_RET(
            request_sz == sizeof(*header_request), -5, "Request buffer must be of vs_fldt_gnfh_header_request_t type");

    CHECK_RET(response_buf_sz > sizeof(*header_response),
              -6,
              "Response buffer must have enough size to store vs_fldt_gnfh_header_response_t structure");

    file_ver = &header_request->version;
    file_type = &file_ver->file_type;

    if (NO_FILE_TYPE == (id = _find_file_type(file_type))) {
        VS_LOG_WARNING("File type %s has not been added to the file type mapping", vs_fldt_file_type_descr(file_type));
        return -7;
    }

    VS_LOG_DEBUG("[FLDT:GNFH] header request : %s", vs_fldt_file_version_descr(file_ver_descr, file_ver));

    file_type_info = _server_file_type_mapping + id;

    CHECK_RET(file_type_info->get_header,
              -8,
              "There is no get_header callback for file type \"%s\"",
              vs_fldt_file_type_descr(file_type));

    CHECK_RET(!file_type_info->get_header(header_request, response_buf_sz, header_response),
              -9,
              "Unable to get last file version information for file type \"%s\"",
              vs_fldt_file_type_descr(file_type));

    *response_sz = sizeof(vs_fldt_gnfh_header_response_t) + header_response->header_size;

    return 0;
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
    const vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfc_chunk_response_t *chunk_response = (vs_fldt_gnfc_chunk_response_t *)response;
    char file_ver_descr[FLDT_FILEVER_BUF];
    size_t id;

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(request_sz, -2);
    CHECK_NOT_ZERO_RET(response, -3);
    CHECK_NOT_ZERO_RET(response_sz, -4);

    CHECK_RET(request_sz == sizeof(*chunk_request), -5, "Request buffer must be of vs_fldt_gnfc_chunk_request_t type");

    CHECK_RET(response_buf_sz > sizeof(*chunk_response),
              -6,
              "Response buffer must have enough size to store vs_fldt_gnfc_chunk_response_t structure");

    file_ver = &chunk_request->version;
    file_type = &file_ver->file_type;

    if (NO_FILE_TYPE == (id = _find_file_type(file_type))) {
        VS_LOG_WARNING("File type %s has not been added to the file type mapping", vs_fldt_file_type_descr(file_type));
        return -7;
    }

    VS_LOG_DEBUG("[FLDT:GNFC] chunk %d request : %s",
                 chunk_request->chunk_id,
                 vs_fldt_file_version_descr(file_ver_descr, file_ver));

    file_type_info = _server_file_type_mapping + id;

    CHECK_RET(file_type_info->get_chunk,
              -8,
              "There is no get_chunk callback for file type \"%s\"",
              vs_fldt_file_type_descr(file_type));

    CHECK_RET(!file_type_info->get_chunk(chunk_request, response_buf_sz, chunk_response),
              -9,
              "Unable to get last file version information for file type \"%s\"",
              vs_fldt_file_type_descr(file_type));

    *response_sz = sizeof(vs_fldt_gnfc_chunk_response_t) + chunk_response->chunk_size;

    return 0;
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
    const vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnff_footer_response_t *footer_response = (vs_fldt_gnff_footer_response_t *)response;
    char file_ver_descr[FLDT_FILEVER_BUF];
    size_t id;

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(request_sz, -2);
    CHECK_NOT_ZERO_RET(response, -3);
    CHECK_NOT_ZERO_RET(response_sz, -4);

    CHECK_RET(
            request_sz == sizeof(*footer_request), -5, "Request buffer must be of vs_fldt_gnff_footer_request_t type");

    CHECK_RET(response_buf_sz > sizeof(*footer_response),
              -6,
              "Response buffer must have enough size to store vs_fldt_gnff_footer_response_t structure");

    file_ver = &footer_request->version;
    file_type = &file_ver->file_type;

    if (NO_FILE_TYPE == (id = _find_file_type(file_type))) {
        VS_LOG_WARNING("File type %s has not been added to the file type mapping", vs_fldt_file_type_descr(file_type));
        return -7;
    }

    VS_LOG_DEBUG("[FLDT:GNFF] footer request : %s", vs_fldt_file_version_descr(file_ver_descr, file_ver));

    file_type_info = _server_file_type_mapping + id;

    CHECK_RET(file_type_info->get_footer,
              -8,
              "There is no get_footer callback for file type \"%s\"",
              vs_fldt_file_type_descr(file_type));

    CHECK_RET(!file_type_info->get_footer(footer_request, response_buf_sz, footer_response),
              -9,
              "Unable to get last file version information for file type \"%s\"",
              vs_fldt_file_type_descr(file_type));

    *response_sz = sizeof(vs_fldt_gnff_footer_response_t) + footer_response->footer_size;

    return 0;
}

/******************************************************************/
int
vs_fldt_add_server_file_type(const vs_fldt_server_file_type_mapping_t *mapping_elem) {

    CHECK_NOT_ZERO_RET(mapping_elem, -1);

    CHECK_RET(_server_file_type_mapping_sz < FLDT_SERVER_FILE_MAPPING_SZ,
              -2,
              "Server's file type mapping array has no free place");
    CHECK_RET(_find_file_type(&mapping_elem->file_type) == NO_FILE_TYPE,
              -3,
              "Such file type has been already added to the mapping list");

    VS_IOT_MEMCPY(_server_file_type_mapping + _server_file_type_mapping_sz, mapping_elem, sizeof(*mapping_elem));

    ++_server_file_type_mapping_sz;

    return 0;
}

/******************************************************************/
int
vs_fldt_broadcast_new_file(const vs_fldt_infv_new_file_request_t *new_file) {
    char filever_descr[FLDT_FILEVER_BUF];

    VS_LOG_DEBUG("*** [FLDT] Broadcast new file version present. %s",
                 vs_fldt_file_version_descr(filever_descr, &new_file->version));

    CHECK_NOT_ZERO_RET(new_file, -1);

    CHECK_RET(_find_file_type(&new_file->version.file_type) != NO_FILE_TYPE,
              -2,
              "Such file type has not been added to the mapping list");

    CHECK_RET(!vs_fldt_send_request(vs_fldt_netif, 0, VS_FLDT_INFV, (const uint8_t *)new_file, sizeof(*new_file)),
              -3,
              "Unable to send FLDT \"INFV\" broadcast request");

    return 0;
}