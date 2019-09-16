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
#include <virgil/iot/update/update.h>
#include <stdlib-config.h>
#include <global-hal.h>

// TODO : make a set!
static size_t _file_type_mapping_array_size = 0;
static vs_fldt_client_file_type_mapping_t _client_file_type_mapping[10];
static vs_fldt_got_file _got_file_callback = NULL;

static vs_fldt_client_file_type_mapping_t *
vs_fldt_get_mapping_elem(const vs_fldt_file_type_t *file_type) {
    vs_fldt_get_mapping_elem_impl(
            vs_fldt_client_file_type_mapping_t, _client_file_type_mapping, _file_type_mapping_array_size, file_type)
}

/******************************************************************/
static int
_check_download_need(const char *opcode,
                     vs_fldt_client_file_type_mapping_t *file_type_info,
                     vs_fldt_file_version_t *current_file_ver,
                     const vs_fldt_file_version_t *new_file_ver,
                     bool *download) {
    const vs_firmware_descriptor_t *file_descr = &file_type_info->file_descr;
    const vs_firmware_version_t *fw_ver = &file_descr->info.version;
    const vs_fldt_file_type_t *file_type = NULL;
    char file_ver_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(new_file_ver, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    file_type = &new_file_ver->file_type;

    FLDT_CHECK(vs_firmware_version_2_vs_fldt_file_version(&current_file_ver, fw_ver),
               "Unable to convert file description");

    current_file_ver->file_type = *file_type;

    VS_LOG_DEBUG("[FLDT:%s] Present file version : %s",
                 opcode,
                 vs_fldt_file_version_descr(file_ver_descr, current_file_ver));

    VS_LOG_DEBUG("[FLDT:%s] New file version : %s", opcode, vs_fldt_file_version_descr(file_ver_descr, new_file_ver));

    *download = vs_fldt_file_is_newer(new_file_ver, current_file_ver);

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
    vs_fldt_file_version_t current_file_ver;
    const vs_fldt_file_version_t *new_file_ver = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_gnfh_header_request_t header_request;
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

    VS_LOG_DEBUG("[FLDT:INFV] Request for new file from gateway " GATEWAY_TEMPLATE " : %s",
                 GATEWAY_ARG(new_file->gateway_mac),
                 vs_fldt_file_version_descr(file_descr, new_file_ver));

    file_type = &new_file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    file_type_info->gateway_mac = new_file->gateway_mac;

    FLDT_CHECK(_check_download_need("INFV", file_type_info, &current_file_ver, new_file_ver, &download), "Unable to check download need");

    if (download) {

        file_type_info->previous_ver = current_file_ver;
        header_request.version = new_file->version;

        VS_LOG_DEBUG("[FLDT] Ask file header for file : %s", vs_fldt_file_version_descr(file_descr, new_file_ver));

        CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_GNFH,
                                        (const uint8_t *)&header_request,
                                        sizeof(header_request)),
                  VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFH\" server request");
    }

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GFTI_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfh_header_request_t new_file;
    vs_fldt_gfti_fileinfo_response_t *file_info = (vs_fldt_gfti_fileinfo_response_t *)response;
    vs_fldt_file_version_t *file_ver = NULL;
    vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    bool download;
    vs_fldt_ret_code_e fldt_ret_code;

    (void)is_ack;

    // TODO : process zero input
    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(response_sz == sizeof(*file_info),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gfti_fileinfo_response_t type");

    file_ver = &file_info->version;

    VS_LOG_DEBUG("[FLDT:GFTI] Response for file from gateway " GATEWAY_TEMPLATE " : %s",
                 GATEWAY_ARG(file_info->gateway_mac),
                 vs_fldt_file_version_descr(file_descr, file_ver));

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    file_type_info->gateway_mac = file_info->gateway_mac;

    FLDT_CHECK(_check_download_need("GFTI", file_type_info, file_ver, &download), "Unable to check download need");

    if (download) {

        new_file.version = *file_ver;

        VS_LOG_DEBUG("[FLDT] Ask file header for file : %s", vs_fldt_file_version_descr(file_descr, file_ver));

        CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_GNFH,
                                        (const uint8_t *)&new_file,
                                        sizeof(new_file)),
                  VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFH\" server request");
    }

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFH_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfh_header_response_t *file_header = (vs_fldt_gnfh_header_response_t *)response;
    vs_fldt_file_version_t *file_ver = NULL;
    vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_gnfd_data_request_t data_request;
    vs_firmware_descriptor_t *file_descr = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_ver_descr[FLDT_FILEVER_BUF];
    int update_ret_code;

    (void)is_ack;

    file_ver = &file_header->version;

    VS_LOG_DEBUG("[FLDT:GNFH] Response file size %d bytes, %s for file : %s",
                 file_header->file_size,
                 file_header->has_footer ? "has footer" : "no footer",
                 vs_fldt_file_version_descr(file_ver_descr, file_ver));

    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_header->file_size, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(file_header->header_size == sizeof(*file_descr),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must store vs_firmware_descriptor_t data");

    CHECK_RET(response_sz >= sizeof(*file_header),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnfh_header_response_t type");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    file_descr = (vs_firmware_descriptor_t *)file_header->header_data;

    file_type_info->file_descr = *file_descr;

    UPDATE_CHECK(vs_update_save_firmware_descriptor(file_type_info->storage_ctx, file_descr),
                 "Unable to save new firmware descriptor");

    VS_IOT_MEMSET(&data_request, 0, sizeof(data_request));

    data_request.offset = 0;
    data_request.version = file_header->version;

    VS_LOG_DEBUG("[FLDT] Ask file data offset %d for file : %s",
                 data_request.offset,
                 vs_fldt_file_version_descr(file_ver_descr, &data_request.version));

    CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                    &file_type_info->gateway_mac,
                                    VS_FLDT_GNFD,
                                    (const uint8_t *)&data_request,
                                    sizeof(data_request)),
              VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"GNFD\" server request");

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
int
vs_fldt_GNFD_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfd_data_response_t *file_data = (vs_fldt_gnfd_data_response_t *)response;
    vs_fldt_file_version_t *file_ver = NULL;
    vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfd_data_request_t data_request;
    vs_fldt_gnff_footer_request_t footer_request;
    char file_ver_descr[FLDT_FILEVER_BUF];
    uint32_t offset;
    uint16_t data_sz;
    int update_ret_code;
    vs_firmware_descriptor_t *file_descr = NULL;

    (void)is_ack;

    file_ver = &file_data->version;

    VS_LOG_DEBUG("[FLDT:GNFD] Response data offset %d, size %d for file : %s",
                 file_data->offset,
                 (int)file_data->data_size,
                 vs_fldt_file_version_descr(file_ver_descr, file_ver));

    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_data->data_size, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(response_sz >= sizeof(*file_data) && (response_sz == sizeof(*file_data) + file_data->data_size),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnfd_data_response_t type");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    file_descr = &file_type_info->file_descr;
    offset = file_data->offset;
    data_sz = file_data->data_size;

    UPDATE_CHECK(vs_update_save_firmware_chunk(
                         file_type_info->storage_ctx, file_descr, (uint8_t *)file_data->data, data_sz, offset),
                 "Unable to save data offset %d size %d for file version %s",
                 offset,
                 data_sz,
                 vs_fldt_file_version_descr(file_ver_descr, file_ver));
    offset += data_sz;

    if (offset < file_descr->firmware_length) {

        // Load next data

        data_request.offset = offset;
        data_request.version = file_data->version;

        VS_LOG_DEBUG("[FLDT] Ask file data offset %d for file : %s",
                     data_request.offset,
                     vs_fldt_file_version_descr(file_ver_descr, &data_request.version));

        CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_GNFD,
                                        (const uint8_t *)&data_request,
                                        sizeof(data_request)),
                  VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFD\" server request");

    } else {

        // Load footer

        footer_request.version = file_data->version;

        CHECK_RET(!vs_fldt_send_request(vs_fldt_netif,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_GNFF,
                                        (const uint8_t *)&footer_request,
                                        sizeof(footer_request)),
                  VS_FLDT_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFF\" server request");
    }

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
static vs_fldt_ret_code_e
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
int
vs_fldt_GNFF_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnff_footer_response_t *file_footer = (vs_fldt_gnff_footer_response_t *)response;
    vs_fldt_file_version_t *file_ver = NULL;
    vs_fldt_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_ver_descr[FLDT_FILEVER_BUF];
    vs_fldt_ret_code_e fldt_ret_code;
    int update_ret_code;
    vs_firmware_descriptor_t *file_descr = NULL;
    vs_fldt_gfti_fileinfo_request_t file_type_request;

    (void)is_ack;

    file_ver = &file_footer->version;

    VS_LOG_DEBUG("[FLDT:GNFF] Response for file : %s. Footer size %d bytes",
                 vs_fldt_file_version_descr(file_ver_descr, file_ver),
                 file_footer->footer_size);

    CHECK_NOT_ZERO_RET(response, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(response_sz >= sizeof(*file_footer) && (response_sz == sizeof(*file_footer) + file_footer->footer_size),
              VS_FLDT_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnff_footer_response_t type");

    file_type = &file_ver->file_type;

    CHECK_RET(file_type_info = vs_fldt_get_mapping_elem(file_type),
              VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    file_descr = &file_type_info->file_descr;

    CHECK_RET(0 == vs_update_save_firmware_footer(
                           file_type_info->storage_ctx, file_descr, (uint8_t *)file_footer->footer_data),
              -2,
              "Unable to save footer for file %s",
              vs_fldt_file_version_descr(file_ver_descr, &file_footer->version));

    if (0 != vs_update_verify_firmware(file_type_info->storage_ctx, file_descr)) {

        VS_LOG_WARNING("Error while verifying firmware for file %s",
                       vs_fldt_file_version_descr(file_ver_descr, &file_footer->version));

        if (0 != vs_update_delete_firmware(file_type_info->storage_ctx, file_descr)) {
            VS_LOG_ERROR("Unable to delete firmware for file %s",
                         vs_fldt_file_version_descr(file_ver_descr, &file_footer->version));
        }

        file_type_request.file_type = file_footer->version.file_type;

        FLDT_CHECK(vs_fldt_ask_file_type_info(&file_type_request), "Unable to ask current file information");

    } else {
        update_ret_code = vs_update_install_firmware(file_type_info->storage_ctx, file_descr);

        if (update_ret_code) {
            VS_LOG_ERROR("Unable to install firmware for file %s",
                         vs_fldt_file_version_descr(file_ver_descr, &file_footer->version));
        }

        _got_file_callback(&file_type_info->previous_ver, file_ver, file_type_info->gateway_mac, 0 == update_ret_code);
    }

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_update_client_file_type(const vs_fldt_file_type_t *file_type, vs_storage_op_ctx_t *storage_ctx) {
    const vs_fldt_fw_add_info_t *fw_add_data = (vs_fldt_fw_add_info_t *)file_type->add_info;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gfti_fileinfo_request_t file_type_request;
    vs_fldt_file_version_t file_ver;
    char file_descr[FLDT_FILEVER_BUF];
    vs_sdmp_fldt_element_e fldt_ret_code;
    int update_ret_code;

    CHECK_NOT_ZERO_RET(file_type, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    VS_LOG_DEBUG("[FLDT] Update file type %s", vs_fldt_file_type_descr(file_descr, file_type));

    file_type_info = vs_fldt_get_mapping_elem(file_type);

    if (!file_type_info) {
        file_type_info = &_client_file_type_mapping[_file_type_mapping_array_size++];
        VS_LOG_DEBUG("[FLDT] File type was not initialized, add new entry. Array size = %d",
                     _file_type_mapping_array_size);
    } else {
        VS_LOG_DEBUG("[FLDT] File type is initialized present, update");
    }

    file_type_info->file_type = *file_type;
    file_type_info->storage_ctx = storage_ctx;
    update_ret_code = vs_update_load_firmware_descriptor(
            storage_ctx, fw_add_data->manufacture_id, fw_add_data->device_type, &file_type_info->file_descr);

    if (0 == update_ret_code) {
        FLDT_CHECK(vs_firmware_version_2_vs_fldt_file_version(&file_ver, &file_type_info->file_descr.info.version),
                   "Unable to convert file version");
        VS_LOG_INFO("[FLDT] Current file version : %s", vs_fldt_file_version_descr(file_descr, &file_ver));
    } else {
        VS_LOG_WARNING("[FLDT] File type was not found by Update library");
        VS_IOT_MEMSET(&file_type_info->file_descr, 0, sizeof(file_type_info->file_descr));
    }

    VS_IOT_MEMSET(&file_type_info->gateway_mac, 0, sizeof(file_type_info->gateway_mac));

    file_type_request.file_type = *file_type;
    FLDT_CHECK(vs_fldt_ask_file_type_info(&file_type_request), "Unable to ask current file information");

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
vs_fldt_ret_code_e
vs_fldt_init_client(vs_fldt_got_file got_file_callback) {

    VS_IOT_ASSERT(got_file_callback);

    vs_fldt_destroy_client();

    _got_file_callback = got_file_callback;
    vs_fldt_is_gateway = false;

    return VS_FLDT_ERR_OK;
}

/******************************************************************/
void
vs_fldt_destroy_client(void) {

    _file_type_mapping_array_size = 0;

}