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

#include <virgil/iot/protocols/sdmp/fldt_private.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <virgil/iot/trust_list/trust_list.h>

static vs_sdmp_service_t _fldt_client = {0};

// TODO : make a set!
typedef struct {
    vs_update_file_type_t type;
    vs_update_file_version_t prev_file_version;
    vs_update_file_version_t cur_file_version;
    vs_update_interface_t *update_context;
    void *file_header;
    size_t file_size;
    vs_mac_addr_t gateway_mac;
} vs_fldt_client_file_type_mapping_t;

static size_t _file_type_mapping_array_size = 0;
static vs_fldt_client_file_type_mapping_t _client_file_type_mapping[10];
static vs_fldt_got_file _got_file_callback = NULL;

/******************************************************************/
static vs_fldt_client_file_type_mapping_t *
_get_mapping_elem(const vs_update_file_type_t *file_type) {
    vs_fldt_client_file_type_mapping_t *file_type_info = _client_file_type_mapping;
    size_t id;

    for (id = 0; id < _file_type_mapping_array_size; ++id, ++file_type_info) {
        if (vs_update_equal_file_type(file_type_info->update_context, &file_type_info->type, file_type)) {
            return file_type_info;
        }
    }

    VS_LOG_WARNING("[FLDT] Unable to find file type specified");

    return NULL;
}

/******************************************************************/
static const char *
_filever_descr(const vs_fldt_client_file_type_mapping_t *file_type_info,
               const vs_update_file_version_t *file_ver,
               char *file_descr,
               size_t descr_buff_size) {
    VS_IOT_ASSERT(file_type_info);
    return file_type_info->update_context->describe_version(file_type_info->update_context->file_context,
                                                            &file_type_info->type,
                                                            file_ver,
                                                            file_descr,
                                                            descr_buff_size,
                                                            true);
}

/******************************************************************/
static const char *
_filetype_descr(const vs_fldt_client_file_type_mapping_t *file_type_info, char *file_descr, size_t descr_buff_size) {
    VS_IOT_ASSERT(file_type_info);
    return vs_update_type_descr(&file_type_info->type, file_type_info->update_context, file_descr, descr_buff_size);
}

/******************************************************************/
static int
_check_download_need(const char *opcode,
                     vs_fldt_client_file_type_mapping_t *file_type_info,
                     vs_update_file_version_t *current_file_ver,
                     const vs_update_file_version_t *new_file_ver,
                     bool *download) {
    char file_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(opcode, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_type_info, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(current_file_ver, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(new_file_ver, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_LOG_DEBUG("[FLDT:%s] Current file version : %s",
                 opcode,
                 _filever_descr(file_type_info, current_file_ver, file_descr, sizeof(file_descr)));

    VS_LOG_DEBUG("[FLDT:%s] New file version : %s",
                 opcode,
                 _filever_descr(file_type_info, new_file_ver, file_descr, sizeof(file_descr)));

    *download = file_type_info->update_context->file_is_newer(
            file_type_info->update_context->file_context, &file_type_info->type, current_file_ver, new_file_ver);

    if (*download) {
        VS_LOG_DEBUG("[FLDT:%s] Need to download new version", opcode);
    } else {
        VS_LOG_DEBUG("[FLDT:%s] No need to download new version", opcode);
    }

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_INFV_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    const vs_fldt_infv_new_file_request_t *new_file = (const vs_fldt_infv_new_file_request_t *)request;
    const vs_update_file_version_t *new_file_ver = NULL;
    const vs_update_file_type_t *file_type = NULL;
    vs_fldt_gnfh_header_request_t header_request;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    bool download;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_code_e fldt_ret_code;

    (void)response;
    (void)response_buf_sz;
    (void)response_sz;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_ZERO_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*new_file),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Unsupported request structure, vs_fldt_infv_new_file_request_t has been waited");

    new_file_ver = &new_file->version;
    file_type = &new_file->type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    VS_LOG_DEBUG("[FLDT:INFV] Request for new file from gateway " FLDT_GATEWAY_TEMPLATE " for %s",
                 FLDT_GATEWAY_ARG(new_file->gateway_mac),
                 _filever_descr(file_type_info, new_file_ver, file_descr, sizeof(file_descr)));

    file_type_info->gateway_mac = new_file->gateway_mac;

    FLDT_CHECK(_check_download_need("INFV", file_type_info, &file_type_info->cur_file_version, new_file_ver, &download),
               "Unable to check download need");

    if (download) {

        file_type_info->prev_file_version = file_type_info->cur_file_version;
        file_type_info->cur_file_version = new_file->version;
        header_request.type = *file_type;
        header_request.version = new_file->version;

        VS_LOG_DEBUG("[FLDT] Ask file header for file %s",
                     _filever_descr(file_type_info, new_file_ver, file_descr, sizeof(file_descr)));

        CHECK_RET(!vs_fldt_send_request(NULL,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_GNFH,
                                        (const uint8_t *)&header_request,
                                        sizeof(header_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFH\" server request");
    }

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFH_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfh_header_response_t *file_header = (vs_fldt_gnfh_header_response_t *)response;
    vs_update_file_version_t *file_ver = NULL;
    vs_update_file_type_t *file_type = NULL;
    vs_fldt_gnfd_data_request_t data_request;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_code_e ret_code;

    (void)is_ack;

    file_ver = &file_header->version;
    file_type = &file_header->type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    VS_LOG_DEBUG("[FLDT:GNFH] Response file size %d bytes, %s, for file %s",
                 file_header->file_size,
                 file_header->has_footer ? "has footer" : "no footer",
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_header->file_size, VS_CODE_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(response_sz >= sizeof(*file_header),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnfh_header_response_t type");

    STATUS_CHECK_RET(file_type_info->update_context->set_header(file_type_info->update_context->file_context,
                                                                file_type,
                                                                file_header->header_data,
                                                                file_header->header_size,
                                                                &file_type_info->file_size),
                     "Unable to set header for file %s",
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    VS_IOT_FREE(file_type_info->file_header);
    file_type_info->file_header = VS_IOT_MALLOC(file_header->header_size);
    CHECK_RET(file_type_info->file_header,
              VS_CODE_ERR_NO_MEMORY,
              "No memory to allocate %lu bytes for file header",
              file_header->header_size);
    VS_IOT_MEMCPY(file_type_info->file_header, file_header->header_data, file_header->header_size);

    VS_IOT_MEMSET(&data_request, 0, sizeof(data_request));

    data_request.offset = 0;
    data_request.type = *file_type;
    data_request.version = file_header->version;

    VS_LOG_DEBUG("[FLDT] Ask file data offset %d for file %s",
                 data_request.offset,
                 _filever_descr(file_type_info, &data_request.version, file_descr, sizeof(file_descr)));

    CHECK_RET(!vs_fldt_send_request(NULL,
                                    &file_type_info->gateway_mac,
                                    VS_FLDT_GNFD,
                                    (const uint8_t *)&data_request,
                                    sizeof(data_request)),
              VS_CODE_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"GNFD\" server request");

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFD_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfd_data_response_t *file_data = (vs_fldt_gnfd_data_response_t *)response;
    vs_update_file_version_t *file_ver = NULL;
    vs_update_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfd_data_request_t data_request;
    vs_fldt_gnff_footer_request_t footer_request;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_code_e ret_code;

    (void)is_ack;

    file_ver = &file_data->version;
    file_type = &file_data->type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

#if DEBUG_CHUNKS
    VS_LOG_DEBUG("[FLDT:GNFD] Response data offset %d, size %d for file %s",
                 file_data->offset,
                 (int)file_data->data_size,
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));
#endif

    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_data->data_size, VS_CODE_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(response_sz >= sizeof(*file_data) && (response_sz == sizeof(*file_data) + file_data->data_size),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnfd_data_response_t type");

    STATUS_CHECK_RET(file_type_info->update_context->set_data(file_type_info->update_context->file_context,
                                                              file_type,
                                                              file_type_info->file_header,
                                                              file_data->data,
                                                              file_data->data_size,
                                                              file_data->offset),
                     "Unable to set header for file %s",
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    if (file_data->next_offset < file_type_info->file_size) {

        // Load next data

        data_request.offset = file_data->next_offset;
        data_request.type = *file_type;
        data_request.version = file_data->version;

#if DEBUG_CHUNKS
        VS_LOG_DEBUG("[FLDT] Ask file data offset %d for file %s",
                     data_request.offset,
                     _filever_descr(file_type_info, &data_request.version, file_descr, sizeof(file_descr)));
#endif

        CHECK_RET(!vs_fldt_send_request(NULL,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_GNFD,
                                        (const uint8_t *)&data_request,
                                        sizeof(data_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFD\" server request");

    } else {

        // Load footer

        footer_request.type = *file_type;
        footer_request.version = file_data->version;

        CHECK_RET(!vs_fldt_send_request(NULL,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_GNFF,
                                        (const uint8_t *)&footer_request,
                                        sizeof(footer_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFF\" server request");
    }

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_code_e
vs_fldt_ask_file_type_info(const char *file_type_descr, const vs_fldt_gfti_fileinfo_request_t *file_type) {
    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_INCORRECT_ARGUMENT);

    VS_LOG_DEBUG("[FLDT] Ask file type information for file type %s", file_type_descr);

    CHECK_RET(!vs_fldt_send_request(
                      NULL, vs_sdmp_broadcast_mac(), VS_FLDT_GFTI, (const uint8_t *)file_type, sizeof(*file_type)),
              VS_CODE_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"GFTI\" server request");

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFF_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnff_footer_response_t *file_footer = (vs_fldt_gnff_footer_response_t *)response;
    vs_update_file_version_t *file_ver = NULL;
    vs_update_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    bool successfully_updated;
    vs_status_code_e ret_code;

    (void)is_ack;

    file_ver = &file_footer->version;
    file_type = &file_footer->type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    VS_LOG_DEBUG("[FLDT:GNFF] Response for file %s. Footer size %d bytes",
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)),
                 file_footer->footer_size);

    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(response_sz >= sizeof(*file_footer) && (response_sz == sizeof(*file_footer) + file_footer->footer_size),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnff_footer_response_t type");

    ret_code = file_type_info->update_context->set_footer(file_type_info->update_context->file_context,
                                                          file_type,
                                                          file_type_info->file_header,
                                                          file_footer->footer_data,
                                                          file_footer->footer_size);
    successfully_updated = ret_code == VS_CODE_OK;

    if (!successfully_updated) {
        VS_LOG_ERROR("Error while processing footer for file %s. Error description : %s",
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)),
                     vs_status_code_descr(ret_code));
    }

    _got_file_callback(file_type,
                       &file_type_info->prev_file_version,
                       file_ver,
                       &file_type_info->gateway_mac,
                       successfully_updated);

    return VS_CODE_OK;
}

/******************************************************************/
vs_status_code_e
vs_fldt_update_client_file_type(const vs_update_file_type_t *file_type, vs_update_interface_t *update_context) {
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gfti_fileinfo_request_t file_type_request;
    vs_update_file_version_t file_ver;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_code_e ret_code;
    size_t header_size;

    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_INCORRECT_ARGUMENT);

    file_type_info = _get_mapping_elem(file_type);

    if (!file_type_info) {
        file_type_info = &_client_file_type_mapping[_file_type_mapping_array_size++];
        VS_LOG_DEBUG("[FLDT] File type was not initialized, add new entry. Array size = %d",
                     _file_type_mapping_array_size);
        VS_IOT_MEMSET(file_type_info, 0, sizeof(*file_type_info));
    } else {
        VS_LOG_DEBUG("[FLDT] File type is initialized present, update");
    }

    file_type_info->type = *file_type;
    file_type_info->update_context = update_context;

    VS_LOG_DEBUG("[FLDT] Update file type %s", _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

    STATUS_CHECK_RET(file_type_info->update_context->get_header_size(
                             file_type_info->update_context->file_context, file_type, &header_size),
                     "Unable to calculate header size for file type %s",
                     file_descr);
    if (header_size) {
        file_type_info->file_header = VS_IOT_MALLOC(header_size);
    }

    file_type_info->file_size = 0;

    ret_code = file_type_info->update_context->get_header(file_type_info->update_context->file_context,
                                                          file_type,
                                                          file_type_info->file_header,
                                                          header_size,
                                                          &header_size);
    if (VS_CODE_OK == ret_code) {
        STATUS_CHECK_RET(
                file_type_info->update_context->get_version(
                        file_type_info->update_context->file_context, file_type, &file_ver),
                "Unable to get version for file %s",
                _filever_descr(file_type_info, &file_type_info->cur_file_version, file_descr, sizeof(file_descr)));

        VS_LOG_INFO("[FLDT] Current file version : %s",
                    _filever_descr(file_type_info, &file_ver, file_descr, sizeof(file_descr)));
        VS_IOT_MEMCPY(&file_type_info->cur_file_version, &file_ver, sizeof(file_ver));
    } else {
        VS_LOG_WARNING("[FLDT] File type was not found by Update library");
        VS_IOT_FREE(file_type_info->file_header);
        file_type_info->file_header = NULL;
    }

    VS_IOT_MEMSET(&file_type_info->gateway_mac, 0, sizeof(file_type_info->gateway_mac));

    file_type_request.type = *file_type;
    STATUS_CHECK_RET(vs_fldt_ask_file_type_info(file_descr, &file_type_request),
                     "Unable to ask current file information");

    return VS_CODE_OK;
}

/******************************************************************/
vs_status_code_e
vs_fldt_init_client(vs_fldt_got_file got_file_callback) {

    VS_IOT_ASSERT(got_file_callback);

    vs_fldt_destroy_client();

    _got_file_callback = got_file_callback;

    return VS_CODE_OK;
}

/******************************************************************/
void
vs_fldt_destroy_client(void) {
    size_t id;
    vs_fldt_client_file_type_mapping_t *file_type_mapping = _client_file_type_mapping;

    for (id = 0; id < _file_type_mapping_array_size; ++id, ++file_type_mapping) {
        file_type_mapping->update_context->free_item(file_type_mapping->update_context->file_context,
                                                     &file_type_mapping->type);
        VS_IOT_FREE(file_type_mapping->file_header);
    }

    _file_type_mapping_array_size = 0;
}

/******************************************************************************/
static int
_fldt_client_request_processor(const struct vs_netif_t *netif,
                               vs_sdmp_element_t element_id,
                               const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {
    (void)netif;

    *response_sz = 0;

    switch (element_id) {

    case VS_FLDT_INFV:
        return vs_fldt_INFV_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GFTI:
    case VS_FLDT_GNFH:
    case VS_FLDT_GNFD:
    case VS_FLDT_GNFF:
        return VS_CODE_OK;

    default:
        VS_IOT_ASSERT(false && "Unsupported command");
        return VS_CODE_ERR_UNSUPPORTED_PARAMETER;
    }
}

/******************************************************************************/
static int
_fldt_client_response_processor(const struct vs_netif_t *netif,
                                vs_sdmp_element_t element_id,
                                bool is_ack,
                                const uint8_t *response,
                                const uint16_t response_sz) {
    (void)netif;

    switch (element_id) {

    case VS_FLDT_INFV:
    case VS_FLDT_GFTI:
        return VS_CODE_OK;

    case VS_FLDT_GNFH:
        return vs_fldt_GNFH_response_processor(is_ack, response, response_sz);

    case VS_FLDT_GNFD:
        return vs_fldt_GNFD_response_processor(is_ack, response, response_sz);

    case VS_FLDT_GNFF:
        return vs_fldt_GNFF_response_processor(is_ack, response, response_sz);

    default:
        VS_IOT_ASSERT(false && "Unsupported command");
        return VS_CODE_ERR_UNSUPPORTED_PARAMETER;
    }
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_fldt_client(void) {

    _fldt_client.user_data = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
    _fldt_client.id = HTONL_IN_COMPILE_TIME('FLDT');
#pragma GCC diagnostic pop
    _fldt_client.request_process = _fldt_client_request_processor;
    _fldt_client.response_process = _fldt_client_response_processor;

    return &_fldt_client;
}

/******************************************************************************/