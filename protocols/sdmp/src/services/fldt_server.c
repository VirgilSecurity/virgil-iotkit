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
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/trust_list/tl_structs.h>

// TODO : make a set!
static size_t _file_type_mapping_array_size = 0;
static vs_fldt_server_file_type_mapping_t _server_file_type_mapping[10];
static vs_fldt_server_add_filetype _add_filetype_callback = NULL;
static vs_mac_addr_t _gateway_mac;

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
    const vs_fldt_fw_add_info_t *fw_add_data = (vs_fldt_fw_add_info_t *)&file_info_request->file_type.add_info;
    const vs_fldt_file_type_t *file_type;
    vs_fldt_server_file_type_mapping_t *file_type_info;
    vs_fldt_gfti_fileinfo_response_t *file_info_response = (vs_fldt_gfti_fileinfo_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;
    vs_tl_element_info_t elem_info;
    vs_tl_header_t *tl_header = NULL;
    int update_ret_code;
    uint16_t data_sz;

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

    file_type_info = vs_fldt_get_mapping_elem(file_type);

    if (!file_type_info) {

        file_type_info = &_server_file_type_mapping[_file_type_mapping_array_size++];

        VS_LOG_DEBUG("[FLDT] File type was not initialized, add new entry. Array size = %d",
                     _file_type_mapping_array_size);

        VS_IOT_ASSERT(_file_type_mapping_array_size <=
                      sizeof(_server_file_type_mapping) / sizeof(_server_file_type_mapping[0]));

        file_type_info->file_type = *file_type;

        CHECK_RET(_add_filetype_callback,
                  VS_FLDT_ERR_NO_CALLBACK,
                  "No add_filetype callback for file type requested by user : %s",
                  vs_fldt_file_type_descr(file_descr, file_type));

        FLDT_CHECK(_add_filetype_callback(file_type, &file_type_info->storage_ctx),
                   "Unable to add file type requested by user : %s",
                   vs_fldt_file_type_descr(file_descr, file_type));
    }

    VS_IOT_MEMSET(file_info_response, 0, sizeof(*file_info_response));

    switch (file_type->file_type_id) {
    case VS_UPDATE_FIRMWARE:
        update_ret_code = vs_update_load_firmware_descriptor(file_type_info->storage_ctx,
                                                             fw_add_data->manufacture_id,
                                                             fw_add_data->device_type,
                                                             &file_type_info->fw_descr);

        switch (update_ret_code) {
        case VS_STORAGE_OK:
            FLDT_CHECK(vs_firmware_version_2_vs_fldt_file_version(
                               &file_info_response->version, file_type, &file_type_info->fw_descr.info.version),
                       "Unable to convert file version");
            break;

        case VS_STORAGE_ERROR_NOT_FOUND:
            VS_LOG_WARNING("Unable to obtain information for file type : %s",
                           vs_fldt_file_type_descr(file_descr, file_type));
            break;

        default:
            VS_LOG_ERROR("Error while obtaining information for file type : %s",
                         vs_fldt_file_type_descr(file_descr, file_type));
            *response_sz = 0;
            return update_ret_code;
        }
        break;

    case VS_UPDATE_TRUST_LIST:
        elem_info.id = VS_TL_ELEMENT_TLH;
        data_sz = sizeof(*tl_header);
        tl_header = &file_type_info->tl_descr;

        CHECK_RET(0 == vs_tl_load_part(&elem_info, (uint8_t *)tl_header, data_sz, &data_sz) &&
                          data_sz == sizeof(*tl_header),
                  -1,
                  "Unable to read Trust List's header");

        file_info_response->version.file_type = *file_type;
        file_info_response->version.tl_ver = htons(tl_header->version);

        break;
    }

    file_info_response->gateway_mac = _gateway_mac;

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
    size_t header_size;

    CHECK_NOT_ZERO_RET(request, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    *response_sz = 0;
    header_response->header_size = 0;
    header_response->file_size = 0;

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

    header_response->version = header_request->version;
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
        header_response->file_size = ntohl(file_type_info->tl_descr.tl_size);
        header_response->header_size = header_size;
        VS_IOT_MEMCPY(header_response->header_data, &file_type_info->tl_descr, header_size);
        break;
    }

    *response_sz = sizeof(*header_response) + header_response->header_size;

    VS_LOG_DEBUG("[FLDT:GNFH] File size %d bytes, %s",
                 header_response->file_size,
                 header_response->has_footer ? "has footer" : "no footer");

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFD_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    const vs_fldt_gnfd_data_request_t *data_request = (const vs_fldt_gnfd_data_request_t *)request;
    const vs_fldt_file_version_t *file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfd_data_response_t *data_response = (vs_fldt_gnfd_data_response_t *)response;
    char file_descr[FLDT_FILEVER_BUF];
    static const uint16_t DATA_SZ = 512;
    vs_tl_element_info_t elem_info;
    uint16_t data_sz;
    int update_ret_code;

    CHECK_NOT_ZERO_RET(request, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    *response_sz = 0;
    data_response->data_size = 0;

    CHECK_RET(request_sz == sizeof(*data_request),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnfd_data_request_t type");

    file_ver = &data_request->version;

    VS_LOG_DEBUG("[FLDT:GNFD] Request for data offset %d for file %s",
                 data_request->offset,
                 vs_fldt_file_version_descr(file_descr, file_ver));

    CHECK_RET(response_buf_sz > sizeof(*data_response),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfd_data_response_t structure");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
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
                     vs_fldt_file_version_descr(file_descr, &data_request->version));
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
                 vs_fldt_file_version_descr(file_descr, file_ver));

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
    static const uint16_t DATA_SZ = 512;
    uint16_t data_sz = 0;
    int update_ret_code;
    vs_tl_element_info_t elem_info;

    CHECK_NOT_ZERO_RET(request, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    *response_sz = 0;
    footer_response->footer_size = 0;

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
                     vs_fldt_file_version_descr(file_descr, &footer_request->version));
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

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_update_server_file_type(const vs_fldt_file_type_t *file_type,
                                vs_storage_op_ctx_t *storage_ctx,
                                bool broadcast_file_info) {
    const vs_fldt_fw_add_info_t *fw_add_data = (vs_fldt_fw_add_info_t *)file_type->add_info;
    vs_fldt_server_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;
    vs_fldt_infv_new_file_request_t new_file;
    int update_ret_code;
    vs_fldt_file_version_t file_ver;
    vs_tl_element_info_t elem_info;
    uint16_t data_sz;

    CHECK_NOT_ZERO_RET(file_type, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    VS_LOG_DEBUG("[FLDT] Update file type %s", vs_fldt_file_type_descr(file_descr, file_type));

    file_type_info = vs_fldt_get_mapping_elem(file_type);

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
        CHECK_NOT_ZERO_RET(storage_ctx, VS_FLDT_ERR_INCORRECT_ARGUMENT);

        update_ret_code = vs_update_load_firmware_descriptor(
                storage_ctx, fw_add_data->manufacture_id, fw_add_data->device_type, &file_type_info->fw_descr);

        if (0 == update_ret_code) {
            FLDT_CHECK(vs_firmware_version_2_vs_fldt_file_version(
                               &file_ver, file_type, &file_type_info->fw_descr.info.version),
                       "Unable to convert file version");
            VS_LOG_INFO("[FLDT] Current file version : %s", vs_fldt_file_version_descr(file_descr, &file_ver));

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
                     vs_fldt_file_version_descr(file_descr, &file_ver));

        CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                        vs_fldt_broadcast_mac_addr,
                                        VS_FLDT_INFV,
                                        (const uint8_t *)&new_file,
                                        sizeof(new_file)),
                  VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"INFV\" broadcast request");
    }

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_init_server(const vs_mac_addr_t *gateway_mac, vs_fldt_server_add_filetype add_filetype) {

    CHECK_NOT_ZERO_RET(add_filetype, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    vs_fldt_destroy_server();

    _gateway_mac = *gateway_mac;
    _add_filetype_callback = add_filetype;

    vs_fldt_is_gateway = true;

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
void
vs_fldt_destroy_server(void) {

    _file_type_mapping_array_size = 0;
}
