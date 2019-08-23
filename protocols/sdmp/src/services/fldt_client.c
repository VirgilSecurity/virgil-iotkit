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

static vs_fldt_client_file_type_mapping_t _client_file_type_mapping[VS_FLDT_FILETYPES_AMOUNT];

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
    vs_fldt_file_version_t present_file_ver;
    const vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    bool download;
    char file_ver_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(request_sz, -2);
    CHECK_NOT_ZERO_RET(response, -3);
    CHECK_NOT_ZERO_RET(response_buf_sz, -4);
    CHECK_NOT_ZERO_RET(response_sz, -5);

    CHECK_RET(request_sz == sizeof(*new_file),
              -6,
              "Unsupported request structure, vs_fldt_infv_new_file_request_t has been waited");

    new_file_ver = &new_file->version;
    file_type = &new_file_ver->file_type;
    file_type_info = &_client_file_type_mapping[file_type->file_type];

    VS_LOG_DEBUG("[FLDT:INFV] Request for new file %s", vs_fldt_file_version_descr(file_ver_descr, new_file_ver));

    FLDT_CHECK(file_type_info,
               set_gateway_mac,
               (&new_file->gateway_mac),
               "Unable to retrieve present file version for file type %s",
               vs_fldt_file_type_descr(file_type));

    FLDT_CHECK(file_type_info,
               get_current_version,
               (file_type, &present_file_ver),
               "Unable to retrieve present file version for file type %s",
               vs_fldt_file_type_descr(file_type));

    download = vs_fldt_file_is_newer(new_file_ver, &present_file_ver);

    VS_LOG_DEBUG("[FLDT:INFV] Current file version : %s. %s",
                 vs_fldt_file_version_descr(file_ver_descr, &present_file_ver),
                 (download ? "Need to download new one." : "No need to download."));

    if (download) {

        FLDT_CHECK(file_type_info,
                   update_file,
                   (new_file),
                   "Unable to notify new file version for file type %s",
                   vs_fldt_file_type_descr(file_type));
    }

    return 0;
}

/******************************************************************/
int
vs_fldt_GFTI_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    const vs_fldt_gfti_fileinfo_response_t *file_info = (const vs_fldt_gfti_fileinfo_response_t *)response;
    const vs_fldt_file_version_t *file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    const vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_ver_descr[FLDT_FILEVER_BUF];

    (void)is_ack;

    CHECK_NOT_ZERO_RET(response, -1);
    CHECK_NOT_ZERO_RET(response_sz, -2);
    CHECK_RET(response_sz == sizeof(*file_info), -3, "Response must be of vs_fldt_gfti_fileinfo_response_t type");

    file_ver = &file_info->version;
    file_type = &file_ver->file_type;
    file_type_info = &_client_file_type_mapping[file_type->file_type];

    VS_LOG_DEBUG("[FLDT:GFTI] Response for file %s", vs_fldt_file_version_descr(file_ver_descr, file_ver));

    FLDT_CHECK(file_type_info,
               get_info,
               (file_info),
               "Unable to process received file information for file %s",
               vs_fldt_file_version_descr(file_ver_descr, file_ver));

    return 0;
}

/******************************************************************/
int
vs_fldt_GNFH_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    const vs_fldt_gnfh_header_response_t *header = (const vs_fldt_gnfh_header_response_t *)response;
    const vs_fldt_file_version_t *file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    const vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_ver_descr[FLDT_FILEVER_BUF];

    (void)is_ack;

    CHECK_NOT_ZERO_RET(response, -1);
    CHECK_NOT_ZERO_RET(response_sz, -2);

    CHECK_RET(response_sz >= sizeof(*header) && (response_sz == sizeof(*header) + header->header_size),
              -3,
              "Response must be of vs_fldt_gnfh_header_response_t type");

    file_ver = &header->version;
    file_type = &file_ver->file_type;
    file_type_info = &_client_file_type_mapping[file_type->file_type];

    VS_LOG_DEBUG(
            "[FLDT:GNFH] Response for file %s. Header : %d bytes data, chunks : %d x %d bytes, footer : %d bytes data",
            vs_fldt_file_version_descr(file_ver_descr, file_ver),
            header->header_size,
            header->chunks_amount,
            header->chunk_size,
            header->footer_size);

    FLDT_CHECK(file_type_info,
               get_header,
               (header),
               "Unable to process received file information for file %s",
               vs_fldt_file_version_descr(file_ver_descr, file_ver));

    return 0;
}

/******************************************************************/
int
vs_fldt_GNFC_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    const vs_fldt_gnfc_chunk_response_t *chunk = (const vs_fldt_gnfc_chunk_response_t *)response;
    const vs_fldt_file_version_t *file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    const vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_ver_descr[FLDT_FILEVER_BUF];

    (void)is_ack;

    CHECK_NOT_ZERO_RET(response, -1);
    CHECK_NOT_ZERO_RET(response_sz, -2);

    CHECK_RET(response_sz >= sizeof(*chunk) && (response_sz == sizeof(*chunk) + chunk->chunk_size),
              -3,
              "Response must be of vs_fldt_gnfc_chunk_response_t type");

    file_ver = &chunk->version;
    file_type = &file_ver->file_type;
    file_type_info = &_client_file_type_mapping[file_type->file_type];

    VS_LOG_DEBUG("[FLDT:GNFC] Response for file %s. Chunk %d, %d bytes",
                 vs_fldt_file_version_descr(file_ver_descr, file_ver),
                 chunk->chunk_id,
                 (int)chunk->chunk_size);

    FLDT_CHECK(file_type_info,
               get_chunk,
               (chunk),
               "Unable to process received file information for file %s",
               vs_fldt_file_version_descr(file_ver_descr, file_ver));

    return 0;
}

/******************************************************************/
int
vs_fldt_GNFF_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    const vs_fldt_gnff_footer_response_t *footer = (const vs_fldt_gnff_footer_response_t *)response;
    const vs_fldt_file_version_t *file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    const vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_ver_descr[FLDT_FILEVER_BUF];

    (void)is_ack;

    CHECK_NOT_ZERO_RET(response, -1);
    CHECK_NOT_ZERO_RET(response_sz, -2);

    CHECK_RET(response_sz >= sizeof(*footer) && (response_sz == sizeof(*footer) + footer->footer_size),
              -3,
              "Response must be of vs_fldt_gnff_footer_response_t type");

    file_ver = &footer->version;
    file_type = &file_ver->file_type;
    file_type_info = &_client_file_type_mapping[file_type->file_type];

    VS_LOG_DEBUG("[FLDT:GNFF] Response for file %s. Footer size %d bytes",
                 vs_fldt_file_version_descr(file_ver_descr, file_ver),
                 footer->footer_size);

    FLDT_CHECK(file_type_info,
               get_footer,
               (footer),
               "Unable to process received file information for file %s",
               vs_fldt_file_version_descr(file_ver_descr, file_ver));

    return 0;
}

/******************************************************************/
int
vs_fldt_add_client_file_type(const vs_fldt_client_file_type_mapping_t *mapping_elem) {
    uint8_t file_type;

    CHECK_NOT_ZERO_RET(mapping_elem, -1);

    file_type = mapping_elem->file_type.file_type;

    CHECK_RET(file_type >= 0 && file_type < VS_FLDT_FILETYPES_AMOUNT,
              -2,
              "Client's file type mapping array has no free place");

    VS_IOT_MEMCPY(&_client_file_type_mapping[file_type], mapping_elem, sizeof(*mapping_elem));

    return 0;
}

/******************************************************************/
int
vs_fldt_ask_file_type_info(const vs_fldt_gfti_fileinfo_request_t *file_type) {

    CHECK_NOT_ZERO_RET(file_type, -1);

    VS_LOG_DEBUG("[FLDT] Ask file type information for file type %s", vs_fldt_file_type_descr(&file_type->file_type));

    CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                    vs_fldt_broadcast_mac_addr,
                                    VS_FLDT_GFTI,
                                    (const uint8_t *)file_type,
                                    sizeof(*file_type)),
              -2,
              "Unable to send FLDT \"GFTI\" server request");

    return 0;
}

/******************************************************************/
int
vs_fldt_ask_file_header(const vs_mac_addr_t *mac, const vs_fldt_gnfh_header_request_t *header_request) {
    char file_type_descr[FLDT_FILEVER_BUF];

    VS_LOG_DEBUG("[FLDT] Ask file header for file version %s",
                 vs_fldt_file_version_descr(file_type_descr, &header_request->version));

    CHECK_NOT_ZERO_RET(mac, -1);
    CHECK_NOT_ZERO_RET(header_request, -2);

    CHECK_RET(!vs_fldt_send_request(
                      vs_fldt_netif, mac, VS_FLDT_GNFH, (const uint8_t *)header_request, sizeof(*header_request)),
              -3,
              "Unable to send FLDT \"GNFH\" server request");

    return 0;
}

/******************************************************************/
int
vs_fldt_ask_file_chunk(const vs_mac_addr_t *mac, vs_fldt_gnfc_chunk_request_t *file_chunk) {
    char file_type_descr[FLDT_FILEVER_BUF];

    VS_LOG_DEBUG("[FLDT] Ask file chunk %d for file type %s",
                 file_chunk->chunk_id,
                 vs_fldt_file_version_descr(file_type_descr, &file_chunk->version));

    CHECK_NOT_ZERO_RET(mac, -1);
    CHECK_NOT_ZERO_RET(file_chunk, -2);

    CHECK_RET(!vs_fldt_send_request(vs_fldt_netif, mac, VS_FLDT_GNFC, (const uint8_t *)file_chunk, sizeof(*file_chunk)),
              -3,
              "Unable to send FLDT \"GNFC\" server request");

    return 0;
}

/******************************************************************/
int
vs_fldt_ask_file_footer(const vs_mac_addr_t *mac, const vs_fldt_gnff_footer_request_t *file_footer) {
    char file_type_descr[FLDT_FILEVER_BUF];

    VS_LOG_DEBUG("[FLDT] Ask file footer for file type %s",
                 vs_fldt_file_version_descr(file_type_descr, &file_footer->version));

    CHECK_NOT_ZERO_RET(mac, -1);
    CHECK_NOT_ZERO_RET(file_footer, -2);

    CHECK_RET(
            !vs_fldt_send_request(vs_fldt_netif, mac, VS_FLDT_GNFF, (const uint8_t *)file_footer, sizeof(*file_footer)),
            -3,
            "Unable to send FLDT \"GNFF\" server request");

    return 0;
}
