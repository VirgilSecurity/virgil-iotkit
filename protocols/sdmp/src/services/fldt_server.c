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
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/protocols/sdmp/fldt_private.h>
#include <virgil/iot/macros/macros.h>
#include <endian-config.h>
#include <virgil/iot/update/update.h>

#define DEBUG_CHUNKS (0)

static vs_sdmp_service_t _fldt_server = {0};

// TODO : make a set!
typedef struct {
    vs_update_file_type_t type;
    vs_update_interface_t *update_context;
    vs_update_file_version_t current_version;
    void *file_header;
    size_t file_size;
} vs_fldt_server_file_type_mapping_t;

static size_t _file_type_mapping_array_size = 0;
static vs_fldt_server_file_type_mapping_t _server_file_type_mapping[10];
static vs_fldt_server_add_filetype _add_filetype_callback = NULL;
static vs_mac_addr_t _gateway_mac;

/******************************************************************/
static vs_fldt_server_file_type_mapping_t *
_get_mapping_elem(const vs_update_file_type_t *file_type) {
    vs_fldt_server_file_type_mapping_t *file_type_info = _server_file_type_mapping;
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
_filever_descr(vs_fldt_server_file_type_mapping_t *file_type_info,
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
_filetype_descr(vs_fldt_server_file_type_mapping_t *file_type_info, char *file_descr, size_t descr_buff_size) {
    if (!file_type_info) {
        return "";
    }
    return vs_update_type_descr(&file_type_info->type, file_type_info->update_context, file_descr, descr_buff_size);
}


/******************************************************************/
static vs_status_code_e
_file_info(const vs_update_file_type_t *file_type,
           vs_update_interface_t *update_context,
           vs_fldt_server_file_type_mapping_t **file_type_info_ptr,
           vs_fldt_file_info_t *file_info) {
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_code_e ret_code;
    size_t file_header_size;

    VS_IOT_ASSERT(file_type);
    VS_IOT_ASSERT(file_type_info_ptr);

    file_type_info = _get_mapping_elem(file_type);

    if (!file_type_info) {
        file_type_info = &_server_file_type_mapping[_file_type_mapping_array_size++];
        VS_LOG_DEBUG("[FLDT] File type was not initialized, add new entry. Array size = %d",
                     _file_type_mapping_array_size);
        VS_IOT_MEMSET(file_type_info, 0, sizeof(*file_type_info));
    } else {
        VS_LOG_DEBUG("[FLDT] File type is initialized present, update");
    }

    file_type_info->type = *file_type;
    file_type_info->update_context = update_context;

    STATUS_CHECK_RET(file_type_info->update_context->get_header_size(
                             file_type_info->update_context->file_context, &file_type_info->type, &file_header_size),
                     "Unable to get header size for file type %s",
                     _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

    if (file_header_size) {
        file_type_info->file_header = VS_IOT_MALLOC(file_header_size);

        STATUS_CHECK_RET(file_type_info->update_context->get_header(file_type_info->update_context->file_context,
                                                                    &file_type_info->type,
                                                                    file_type_info->file_header,
                                                                    file_header_size,
                                                                    &file_header_size),
                         "Unable to get header for file type %s",
                         _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

        STATUS_CHECK_RET(file_type_info->update_context->get_file_size(file_type_info->update_context->file_context,
                                                                       &file_type_info->type,
                                                                       file_type_info->file_header,
                                                                       &file_type_info->file_size),
                         "Unable to get header size for file type %s",
                         _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

        STATUS_CHECK_RET(file_type_info->update_context->get_version(file_type_info->update_context->file_context,
                                                                     &file_type_info->type,
                                                                     &file_type_info->current_version),
                         "Unable to get file version for file type %s",
                         _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));
    } else {
        VS_LOG_WARNING("There is no header data for file type %s",
                       _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));
    }

    VS_LOG_DEBUG("[FLDT] Update file %s",
                 _filever_descr(file_type_info, &file_type_info->current_version, file_descr, sizeof(file_descr)));

    memset(file_info, 0, sizeof(*file_info));

    file_info->type = *file_type;
    file_info->version = file_type_info->current_version;
    file_info->gateway_mac = _gateway_mac;

    *file_type_info_ptr = file_type_info;

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GFTI_request_processor(const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    const vs_fldt_gfti_fileinfo_request_t *file_info_request = (const vs_fldt_gfti_fileinfo_request_t *)request;
    const vs_update_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_code_e ret_code;
    vs_update_interface_t *update_context;
    vs_fldt_file_info_t *file_info = (vs_fldt_file_info_t *)response;

    (void)response_buf_sz;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(request_sz == sizeof(*file_info_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gfti_fileinfo_request_t type");
    CHECK_RET(response_buf_sz >= sizeof(*file_info),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must be of vs_fldt_file_info_t type");

    file_type = &file_info_request->type;
    file_type_info = _get_mapping_elem(file_type);

    if (!file_type_info) {

        CHECK_RET(_add_filetype_callback,
                  VS_CODE_ERR_NO_CALLBACK,
                  "No add_filetype callback for file type requested by user : %s",
                  _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

        STATUS_CHECK_RET(_add_filetype_callback(file_type, &update_context),
                         "Unable to add file type requested by user : %s",
                         _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));
    } else {
        update_context = file_type_info->update_context;
    }

    STATUS_CHECK_RET(_file_info(file_type, update_context, &file_type_info, file_info),
                     "Unable to get information for file %s",
                     _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

    *response_sz = sizeof(*file_info);

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFH_request_processor(const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    const vs_fldt_gnfh_header_request_t *header_request = (const vs_fldt_gnfh_header_request_t *)request;
    const vs_update_file_version_t *file_ver = NULL;
    const vs_update_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfh_header_response_t *header_response = (vs_fldt_gnfh_header_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    size_t header_size;
    vs_status_code_e ret_code;
    bool has_footer;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    *response_sz = 0;
    VS_IOT_MEMSET(header_response, 0, sizeof(*header_response));

    CHECK_RET(request_sz == sizeof(*header_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnfh_header_request_t type");

    file_ver = &header_request->version;
    file_type = &header_request->type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    VS_LOG_DEBUG("[FLDT:GNFH] Request for header for file version %s",
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    CHECK_RET(response_buf_sz > sizeof(*header_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfh_header_response_t structure");

    header_response->type = *file_type;
    header_response->version = header_request->version;
    if (file_type_info->file_size > UINT32_MAX) {
        VS_LOG_ERROR("File size %d is bigger that file_type_info->file_size %d can transmit",
                     file_type_info->file_size,
                     UINT32_MAX);
    } else {
        header_response->file_size = file_type_info->file_size;
    }

    STATUS_CHECK_RET(file_type_info->update_context->has_footer(
                             file_type_info->update_context->file_context, &file_type_info->type, &has_footer),
                     "Unable to check that there is footer for file %s",
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));
    header_response->has_footer = has_footer != 0;

    STATUS_CHECK_RET(file_type_info->update_context->get_header_size(
                             file_type_info->update_context->file_context, &file_type_info->type, &header_size),
                     "Unable to get header size for file %s",
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));
    if (header_size > UINT16_MAX) {
        VS_LOG_ERROR("Header size %d is bigger that vs_fldt_gnfh_header_response_t.header_size %d can transmit",
                     header_size,
                     UINT16_MAX);
    } else {
        header_response->header_size = header_size;
    }

    if (sizeof(vs_fldt_gnfh_header_response_t) + header_size > response_buf_sz) {
        VS_LOG_ERROR(
                "Buffer size %d for storing vs_fldt_gnfh_header_response_t is not enough to store %d bytes of data",
                response_buf_sz,
                sizeof(vs_fldt_gnfh_header_response_t) + header_size);
    } else {
        VS_IOT_MEMCPY(header_response->header_data, file_type_info->file_header, header_size);
        *response_sz = sizeof(*header_response) + header_response->header_size;
    }

    VS_LOG_DEBUG("[FLDT:GNFH] Header size %d, file size %d bytes, %s",
                 header_response->header_size,
                 header_response->file_size,
                 header_response->has_footer ? "has footer" : "no footer");

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFD_request_processor(const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    const vs_fldt_gnfd_data_request_t *data_request = (const vs_fldt_gnfd_data_request_t *)request;
    const vs_update_file_version_t *file_ver = NULL;
    const vs_update_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfd_data_response_t *data_response = (vs_fldt_gnfd_data_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    static const size_t DATA_SZ = 512;
    ssize_t max_data_size_to_read;
    size_t data_size_read;
    vs_status_code_e ret_code;
    size_t cur_offset;
    size_t next_offset;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    *response_sz = 0;
    VS_IOT_MEMSET(data_response, 0, sizeof(*data_response));

    CHECK_RET(request_sz == sizeof(*data_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnfd_data_request_t type");

    file_ver = &data_request->version;
    file_type = &data_request->type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

#if DEBUG_CHUNKS
    VS_LOG_DEBUG("[FLDT:GNFD] Request for data offset %d for file %s",
                 data_request->offset,
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));
#endif

    CHECK_RET(response_buf_sz > sizeof(*data_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfd_data_response_t structure");

    CHECK_RET(data_request->offset < file_type_info->file_size,
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request's data offset %d is not inside file data size %d",
              data_request->offset,
              file_type_info->file_size);

    data_response->version = data_request->version;
    data_response->type = data_request->type;
    data_response->offset = data_request->offset;

    max_data_size_to_read = response_buf_sz - sizeof(*data_response);
    if (max_data_size_to_read > DATA_SZ) {
        max_data_size_to_read = DATA_SZ;
    }
    cur_offset = data_request->offset;

    STATUS_CHECK_RET(file_type_info->update_context->get_data(file_type_info->update_context->file_context,
                                                              &file_type_info->type,
                                                              file_type_info->file_header,
                                                              data_response->data,
                                                              max_data_size_to_read,
                                                              &data_size_read,
                                                              cur_offset),
                     "Unable to read %d (%Xh) data items starting from offset %d (%Xh) data items for file %s",
                     max_data_size_to_read,
                     cur_offset,
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    data_response->data_size = data_size_read;

    STATUS_CHECK_RET(file_type_info->update_context->inc_data_offset(file_type_info->update_context->file_context,
                                                                     &file_type_info->type,
                                                                     cur_offset,
                                                                     data_size_read,
                                                                     &next_offset),
                     "Unable to retrieve offset for file %s",
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    if (next_offset > UINT32_MAX) {
        VS_LOG_ERROR("Offset %d is bigger that vs_fldt_gnfd_data_response_t.next_offset %d can transmit",
                     next_offset,
                     UINT32_MAX);
    } else {
        data_response->next_offset = next_offset;
    }

    *response_sz = sizeof(vs_fldt_gnfd_data_response_t) + data_response->data_size;
#if DEBUG_CHUNKS
    VS_LOG_DEBUG("[FLDT:GNFD] File data offset %d data items of %d data items size has been sent for file %s",
                 data_response->offset,
                 data_response->data_size,
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));
#endif

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFF_request_processor(const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    const vs_fldt_gnff_footer_request_t *footer_request = (const vs_fldt_gnff_footer_request_t *)request;
    const vs_update_file_version_t *file_ver = NULL;
    const vs_update_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnff_footer_response_t *footer_response = (vs_fldt_gnff_footer_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    static const uint16_t DATA_SZ = 512;
    size_t data_size;
    vs_status_code_e ret_code;
    bool has_footer;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    *response_sz = 0;
    VS_IOT_MEMSET(footer_response, 0, sizeof(*footer_response));

    CHECK_RET(request_sz == sizeof(*footer_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnff_footer_request_t type");

    file_ver = &footer_request->version;
    file_type = &footer_request->type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    VS_LOG_DEBUG("[FLDT:GNFF] Footer request for %s",
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    CHECK_RET(response_buf_sz > sizeof(*footer_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnff_footer_response_t structure");

    STATUS_CHECK_RET(file_type_info->update_context->has_footer(
                             file_type_info->update_context->file_context, &file_type_info->type, &has_footer),
                     "Unable to check that there is footer for file %s",
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    CHECK_RET(has_footer,
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "There is no footer for file %s",
              _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    footer_response->type = footer_request->type;
    footer_response->version = footer_request->version;

    data_size = response_buf_sz - sizeof(vs_fldt_gnff_footer_response_t);
    if (data_size > DATA_SZ) {
        data_size = DATA_SZ;
    }

    STATUS_CHECK_RET(file_type_info->update_context->get_footer(file_type_info->update_context->file_context,
                                                                &file_type_info->type,
                                                                file_type_info->file_header,
                                                                footer_response->footer_data,
                                                                data_size,
                                                                &data_size),
                     "Unable to read %d (%Xh) footer data items for file %s",
                     data_size,
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    footer_response->footer_size = data_size;

    *response_sz = sizeof(vs_fldt_gnff_footer_response_t) + footer_response->footer_size;

    return VS_CODE_OK;
}

/******************************************************************/
vs_status_code_e
vs_fldt_update_server_file_type(const vs_update_file_type_t *file_type,
                                vs_update_interface_t *update_context,
                                bool broadcast_file_info) {
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_file_info_t new_file;
    vs_status_code_e ret_code;

    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(update_context, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(_file_info(file_type, update_context, &file_type_info, &new_file),
                     "Unable to prepare information about file %s",
                     _filever_descr(file_type_info, &file_type_info->current_version, file_descr, sizeof(file_descr)));

    if (broadcast_file_info) {
        VS_LOG_DEBUG("[FLDT] Broadcast new file information : %s",
                     _filever_descr(file_type_info, &file_type_info->current_version, file_descr, sizeof(file_descr)));

        CHECK_RET(!vs_fldt_send_request(
                          NULL, vs_sdmp_broadcast_mac(), VS_FLDT_INFV, (const uint8_t *)&new_file, sizeof(new_file)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"INFV\" broadcast request");
    }

    return VS_CODE_OK;
}

/******************************************************************/
vs_status_code_e
vs_fldt_init_server(const vs_mac_addr_t *gateway_mac, vs_fldt_server_add_filetype add_filetype) {

    CHECK_NOT_ZERO_RET(add_filetype, VS_CODE_ERR_INCORRECT_ARGUMENT);

    vs_fldt_destroy_server();

    _gateway_mac = *gateway_mac;
    _add_filetype_callback = add_filetype;

    return VS_CODE_OK;
}

/******************************************************************/
void
vs_fldt_destroy_server(void) {
    size_t id;
    vs_fldt_server_file_type_mapping_t *file_type_mapping = _server_file_type_mapping;

    for (id = 0; id < _file_type_mapping_array_size; ++id, ++file_type_mapping) {
        file_type_mapping->update_context->free_item(file_type_mapping->update_context->file_context,
                                                     &file_type_mapping->type);
        VS_IOT_FREE(file_type_mapping->file_header);
    }

    _file_type_mapping_array_size = 0;
}

/******************************************************************************/
static int
_fldt_server_request_processor(const struct vs_netif_t *netif,
                               vs_sdmp_element_t element_id,
                               const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    *response_sz = 0;

    switch (element_id) {

    case VS_FLDT_INFV:
        return VS_SDMP_COMMAND_NOT_SUPPORTED;

    case VS_FLDT_GFTI:
        return vs_fldt_GFTI_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GNFH:
        return vs_fldt_GNFH_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GNFD:
        return vs_fldt_GNFD_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GNFF:
        return vs_fldt_GNFF_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    default:
        return VS_SDMP_COMMAND_NOT_SUPPORTED;
    }
}

/******************************************************************************/
static int
_fldt_server_response_processor(const struct vs_netif_t *netif,
                                vs_sdmp_element_t element_id,
                                bool is_ack,
                                const uint8_t *response,
                                const uint16_t response_sz) {

    switch (element_id) {

    case VS_FLDT_INFV:
    case VS_FLDT_GFTI:
    case VS_FLDT_GNFD:
    case VS_FLDT_GNFF:
        return VS_SDMP_COMMAND_NOT_SUPPORTED;

    default:
        VS_LOG_ERROR("Unsupported FLDT command");
        VS_IOT_ASSERT(false);
        return VS_SDMP_COMMAND_NOT_SUPPORTED;
    }
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_fldt_server(void) {
    _fldt_server.user_data = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
    _fldt_server.id = HTONL_IN_COMPILE_TIME('FLDT');
#pragma GCC diagnostic pop
    _fldt_server.request_process = _fldt_server_request_processor;
    _fldt_server.response_process = _fldt_server_response_processor;
    _fldt_server.periodical_process = NULL;

    return &_fldt_server;
}

/******************************************************************************/