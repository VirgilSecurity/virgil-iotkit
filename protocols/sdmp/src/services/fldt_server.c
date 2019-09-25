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

static vs_sdmp_service_t _fldt_server = {0};

// TODO : make a set!
typedef struct {
    vs_update_file_type_t type;
    vs_update_interface_t update_context;
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
        if (!VS_IOT_MEMCMP(&file_type_info->type, file_type, sizeof(*file_type))) {
            return file_type_info;
        }
    }

    VS_LOG_WARNING("[FLDT] Unable to find file type specified");

    return NULL;
}

/******************************************************************/
static const char *
_filever_descr(const vs_fldt_server_file_type_mapping_t *file_type_info, const vs_update_file_version_t *file_ver, char *file_descr, size_t descr_buff_size){
            VS_IOT_ASSERT(file_type_info);
    return file_type_info->update_context.describe_version(file_type_info->update_context.file_context, &file_type_info->type, file_ver, file_descr, descr_buff_size, true);
}

/******************************************************************/
static const char *
_filetype_descr(const vs_fldt_server_file_type_mapping_t *file_type_info, char *file_descr, size_t descr_buff_size){
    VS_IOT_ASSERT(file_type_info);
    return vs_update_type_descr(&file_type_info->type, &file_type_info->update_context, file_descr, descr_buff_size);
}

/******************************************************************/
int
vs_fldt_GFTI_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    const vs_fldt_gfti_fileinfo_request_t *file_info_request = (const vs_fldt_gfti_fileinfo_request_t *)request;
    const vs_update_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info;
    vs_fldt_gfti_fileinfo_response_t *file_info_response = (vs_fldt_gfti_fileinfo_response_t *)response;
    size_t file_header_size;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_code_e ret_code;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*file_info_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gfti_fileinfo_request_t type");

    file_type = &file_info_request->type;
    file_type_info = _get_mapping_elem(file_type);

    if (!file_type_info) {

        file_type_info = &_server_file_type_mapping[_file_type_mapping_array_size++];

        VS_LOG_DEBUG("[FLDT] File type was not initialized, add new entry. Array size = %d",
                     _file_type_mapping_array_size);

                VS_IOT_ASSERT(_file_type_mapping_array_size <=
                              sizeof(_server_file_type_mapping) / sizeof(_server_file_type_mapping[0]));

        VS_IOT_MEMSET(file_type_info, 0, sizeof(*file_type_info));

        file_type_info->type = *file_type;

        CHECK_RET(_add_filetype_callback,
                  VS_CODE_ERR_NO_CALLBACK,
                  "No add_filetype callback for file type requested by user : %s",
                  _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

        STATUS_CHECK_RET(_add_filetype_callback(file_type, &file_type_info->update_context),
                   "Unable to add file type requested by user : %s",
                   _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

        STATUS_CHECK_RET(file_type_info->update_context.get_header_size(file_type_info->update_context.file_context, file_type, &file_header_size),
                         "Unable to get header size for file type %s",
                         _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

        if(file_header_size) {
            file_type_info->file_header = VS_IOT_MALLOC(file_header_size);

            STATUS_CHECK_RET(
                    file_type_info->update_context.get_header(file_type_info->update_context.file_context, file_type,
                                                              &file_type_info->file_header, file_header_size,
                                                              &file_header_size),
                    "Unable to get header for file type %s",
                    _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

            STATUS_CHECK_RET(file_type_info->update_context.get_version(file_type_info->update_context.file_context, file_type, &file_type_info->current_version),
                    "Unable to get file version for file type %s",
                             _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));
        } else {
            VS_LOG_WARNING("There is no header data for file type %s",
                           _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));
        }
    }

    VS_LOG_DEBUG("[FLDT:GFTI] Request for %s", _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

    CHECK_RET(response_buf_sz >= sizeof(*file_info_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gfti_fileinfo_response_t structure");

    VS_IOT_MEMSET(file_info_response, 0, sizeof(*file_info_response));
    file_info_response->type = *file_type;
    file_info_response->gateway_mac = _gateway_mac;

    if(!file_type_info->file_header){
        VS_LOG_WARNING("There is no header data for file type %s",
                       _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));
    } else {
        file_info_response->version = file_type_info->current_version;
    }

    VS_LOG_DEBUG("[FLDT:GFTI] Server file information : %s",
                 _filever_descr(file_descr, &file_info_response->version));

    *response_sz = sizeof(*file_info_response);

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFH_request_processing(const uint8_t *request,
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

    VS_LOG_DEBUG("[FLDT:GNFH] Request for header for file version %s",
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    CHECK_RET(response_buf_sz > sizeof(*header_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfh_header_response_t structure");

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    header_response->type = *file_type;
    header_response->version = header_request->version;
    if(file_type_info->file_size > UINT32_MAX) {
        VS_LOG_ERROR("File size %d cannot be save as uin32_t", file_type_info->file_size);
    } else {
        header_response->file_size = file_type_info->file_size;
    }
    // TODO : check footer presence for non-firmware type !!!
    header_response->has_footer = true;

    switch (file_type->file_type_id) {
        case VS_UPDATE_FIRMWARE:
            header_size = sizeof(file_type_info->fw_descr);
            header_response->file_size = file_type_info->fw_descr.firmware_length;
            header_response->header_size = header_size;
            VS_IOT_MEMCPY(header_response->header_data, &file_type_info->fw_descr, header_size);
            break;

        case VS_UPDATE_TRUST_LIST:
            header_size = sizeof(file_type_info->tl_descr);
            header_response->file_size = VS_IOT_NTOHL(file_type_info->tl_descr.tl_size);
            header_response->header_size = header_size;
            VS_IOT_MEMCPY(header_response->header_data, &file_type_info->tl_descr, header_size);
            break;
    }

    *response_sz = sizeof(*header_response) + header_response->header_size;

    VS_LOG_DEBUG("[FLDT:GNFH] File size %d bytes, %s",
                 header_response->file_size,
                 header_response->has_footer ? "has footer" : "no footer");

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFD_request_processing(const uint8_t *request,
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
    static const uint16_t DATA_SZ = 512;
    vs_tl_element_info_t elem_info;
    uint16_t data_sz;
    int update_ret_code;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    *response_sz = 0;
    data_response->data_size = 0;

    CHECK_RET(request_sz == sizeof(*data_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnfd_data_request_t type");

    file_ver = &data_request->version;

    VS_LOG_DEBUG("[FLDT:GNFD] Request for data offset %d for file %s",
                 data_request->offset,
                 _filever_descr(file_descr, file_ver));

    CHECK_RET(response_buf_sz > sizeof(*data_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfd_data_response_t structure");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    data_response->version = data_request->version;
    data_response->offset = data_request->offset;

    // TODO : make size dependant on buffer size !!!
    data_sz = DATA_SZ;
    switch (file_type->file_type_id) {
        case VS_UPDATE_FIRMWARE:
            if (data_request->offset >= file_type_info->fw_descr.firmware_length) {
                data_sz = 0;
                break;
            }

            UPDATE_CHECK(vs_update_load_firmware_chunk(file_type_info->storage_ctx,
                                                       &file_type_info->fw_descr,
                                                       data_request->offset,
                                                       data_response->data,
                                                       data_sz,
                                                       &data_sz),
                         "Unable to get firmware data with offset %d size %d for file version %s",
                         data_request->offset,
                         response_buf_sz,
                         _filever_descr(file_descr, &data_request->version));
            break;

        case VS_UPDATE_TRUST_LIST:
            if (data_request->offset >= file_type_info->tl_descr.pub_keys_count) {
                data_sz = 0;
                break;
            }

            elem_info.id = VS_TL_ELEMENT_TLC;
            elem_info.index = data_request->offset;

            CHECK_RET(0 == vs_tl_load_part(&elem_info, data_response->data, data_sz, &data_sz) && data_sz > 0,
                      -1,
                      "Unable to load Trust List's public key %d",
                      data_request->offset);
            break;
    }

    data_response->data_size = data_sz;

    *response_sz = sizeof(vs_fldt_gnfd_data_response_t) + data_response->data_size;

    VS_LOG_DEBUG("[FLDT:GNFD] File data offset %d size %d has been sent for file %s",
                 data_response->offset,
                 data_response->data_size,
                 _filever_descr(file_descr, file_ver));

    return VS_CODE_OK;
}

/******************************************************************/
int
vs_fldt_GNFF_request_processing(const uint8_t *request,
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
    uint16_t data_sz = 0;
    int update_ret_code;
    vs_tl_element_info_t elem_info;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    *response_sz = 0;
    footer_response->footer_size = 0;

    CHECK_RET(request_sz == sizeof(*footer_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnff_footer_request_t type");

    file_ver = &footer_request->version;

    VS_LOG_DEBUG("[FLDT:GNFF] Footer request for %s", _filever_descr(file_descr, file_ver));

    CHECK_RET(response_buf_sz > sizeof(*footer_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnff_footer_response_t structure");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    footer_response->version = footer_request->version;

    // TODO : need a way to detect data size !!!
    data_sz = DATA_SZ;

    switch (file_type->file_type_id) {
        case VS_UPDATE_FIRMWARE:
            UPDATE_CHECK(vs_update_load_firmware_footer(file_type_info->storage_ctx,
                                                        &file_type_info->fw_descr,
                                                        footer_response->footer_data,
                                                        data_sz,
                                                        &data_sz),
                         "Unable to get firmware footer for file version %s",
                         _filever_descr(file_descr, &footer_request->version));
            break;

        case VS_UPDATE_TRUST_LIST:
            elem_info.id = VS_TL_ELEMENT_TLF;

            CHECK_RET(0 == vs_tl_load_part(&elem_info, footer_response->footer_data, data_sz, &data_sz),
                      -1,
                      "Unable to load Trust List's footer");
            break;
    }

    footer_response->footer_size = data_sz;

    *response_sz = sizeof(vs_fldt_gnff_footer_response_t) + footer_response->footer_size;

    return VS_CODE_OK;
}

/******************************************************************/
vs_status_code_e
vs_fldt_update_server_file_type(const vs_update_file_type_t *file_type,
                                void *update_ctx,
                                bool broadcast_file_info) {
    const vs_fldt_fw_add_info_t *fw_add_data = (vs_fldt_fw_add_info_t *)file_type->add_info;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_code_e fldt_ret_code;
    vs_fldt_infv_new_file_request_t new_file;
    int update_ret_code;
    vs_update_file_version_t file_ver;
    vs_tl_element_info_t elem_info;
    uint16_t data_sz;

    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_INCORRECT_ARGUMENT);

    VS_LOG_DEBUG("[FLDT] Update file type %s", vs_fldt_file_type_descr(file_descr, file_type));

    file_type_info = _get_mapping_elem(file_type);

    if (!file_type_info) {
        file_type_info = &_server_file_type_mapping[_file_type_mapping_array_size++];
        VS_LOG_DEBUG("[FLDT] File type was not initialized, add new entry. Array size = %d",
                     _file_type_mapping_array_size);
    } else {
        VS_LOG_DEBUG("[FLDT] File type is initialized present, update");
    }

    file_type_info->file_type = *file_type;
    file_type_info->storage_ctx = storage_ctx;

    VS_IOT_MEMSET(&file_ver, 0, sizeof(file_ver));

    switch (file_type->file_type_id) {
        case VS_UPDATE_FIRMWARE:
            CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_ARGUMENT);

            update_ret_code = vs_update_load_firmware_descriptor(
                    storage_ctx, fw_add_data->manufacture_id, fw_add_data->device_type, &file_type_info->fw_descr);

            if (0 == update_ret_code) {
                FLDT_CHECK(vs_firmware_version_2_vs_fldt_file_version(
                        &file_ver, file_type, &file_type_info->fw_descr.info.version),
                           "Unable to convert file version");
                VS_LOG_INFO("[FLDT] Current file version : %s", _filever_descr(file_descr, &file_ver));

            } else {
                VS_LOG_WARNING("[FLDT] File type was not found by Update library");
                VS_IOT_MEMSET(&file_type_info->fw_descr, 0, sizeof(file_type_info->fw_descr));

                broadcast_file_info = false;
            }

            break;

        case VS_UPDATE_TRUST_LIST:
            elem_info.id = VS_TL_ELEMENT_TLH;

            data_sz = sizeof(file_type_info->tl_descr);
            CHECK_RET(0 == vs_tl_load_part(&elem_info, (uint8_t *)&file_type_info->tl_descr, data_sz, &data_sz) &&
                      data_sz == sizeof(file_type_info->tl_descr),
                      -1,
                      "Unable to load Trust List's header");

            file_ver.file_type.file_type_id = VS_UPDATE_TRUST_LIST;
            file_ver.tl_ver = file_type_info->tl_descr.version;
    }

    if (broadcast_file_info) {
        memset(&new_file, 0, sizeof(new_file));

        new_file.version = file_ver;
        new_file.gateway_mac = _gateway_mac;

        VS_LOG_DEBUG("[FLDT] Broadcast new file information. File version : %s",
                     _filever_descr(file_descr, &file_ver));

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
            return vs_fldt_INFV_request_processing(request, request_sz, response, response_buf_sz, response_sz);

        case VS_FLDT_GFTI:
            return vs_fldt_GFTI_request_processing(request, request_sz, response, response_buf_sz, response_sz);

        case VS_FLDT_GNFH:
            return vs_fldt_GNFH_request_processing(request, request_sz, response, response_buf_sz, response_sz);

        case VS_FLDT_GNFD:
            return vs_fldt_GNFD_request_processing(request, request_sz, response, response_buf_sz, response_sz);

        case VS_FLDT_GNFF:
            return vs_fldt_GNFF_request_processing(request, request_sz, response, response_buf_sz, response_sz);

        default:
                    VS_IOT_ASSERT(false && "Unsupported command");
            return VS_FLDT_ERR_UNSUPPORTED_PARAMETER;
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
            return VS_CODE_OK;

        case VS_FLDT_GFTI:
            return vs_fldt_GFTI_response_processor(is_ack, response, response_sz);

        case VS_FLDT_GNFH:
            return vs_fldt_GNFH_response_processor(is_ack, response, response_sz);

        case VS_FLDT_GNFD:
            return vs_fldt_GNFD_response_processor(is_ack, response, response_sz);

        case VS_FLDT_GNFF:
            return vs_fldt_GNFF_response_processor(is_ack, response, response_sz);

        default:
                    VS_IOT_ASSERT(false && "Unsupported command");
            return VS_FLDT_ERR_UNSUPPORTED_PARAMETER;
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

    return &_fldt_server;
}

/******************************************************************************/