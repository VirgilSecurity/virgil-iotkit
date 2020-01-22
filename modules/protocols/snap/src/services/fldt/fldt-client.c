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

#if FLDT_CLIENT

#include <virgil/iot/protocols/snap/fldt/fldt-private.h>
#include <virgil/iot/protocols/snap/fldt/fldt-client.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <virgil/iot/trust_list/trust_list.h>

#define DEBUG_CHUNKS (0)

static vs_snap_service_t _fldt_client = {0};

#define VS_FLDT_RETRY_MAX (5)
#define VS_FLDT_WAIT_MAX (10) // Seconds

#define VS_FLDT_REQUEST_SZ_MAX (150)

// TODO : This setting might be moved to some config
#define CLIENT_FILE_TYPE_ARRAY_SIZE (10)

typedef struct {
    bool in_progress;
    int retry_used;
    int tick_cnt;
    uint32_t expected_offset;
    vs_mac_addr_t gateway_mac;
    uint32_t command;
    uint8_t data[VS_FLDT_REQUEST_SZ_MAX];
    uint16_t data_sz;
} vs_fldt_update_ctx_t;

typedef struct {
    vs_update_file_type_t type;
    vs_file_version_t prev_file_version;
    vs_file_version_t cur_file_version;
    vs_update_interface_t *update_interface;
    void *file_header;
    uint32_t file_size;
    vs_mac_addr_t gateway_mac;
    vs_fldt_update_ctx_t update_ctx;
} vs_fldt_client_file_type_mapping_t;

static uint32_t _file_type_mapping_array_size = 0;
static vs_fldt_client_file_type_mapping_t _client_file_type_mapping[CLIENT_FILE_TYPE_ARRAY_SIZE];
static vs_fldt_got_file _got_file_callback = NULL;

/******************************************************************/
static void
_update_process_reset(vs_fldt_client_file_type_mapping_t *object_info) {
    CHECK_NOT_ZERO(object_info);
    vs_fldt_update_ctx_t *update_ctx = &object_info->update_ctx;

    if (object_info->update_ctx.in_progress) {
        switch (object_info->update_ctx.command) {
        case VS_FLDT_GNFH:
        case VS_FLDT_GNFD:
        case VS_FLDT_GNFF:
            object_info->update_interface->delete_object(object_info->update_interface->storage_context,
                                                         &object_info->type);
            break;
        default:
            break;
        }
    }

    VS_FLDT_PRINT_DEBUG(object_info->type.type, update_ctx->command, "_update_process_reset");
    VS_IOT_MEMSET(update_ctx, 0, sizeof(*update_ctx));
terminate:;
}

/******************************************************************/
static vs_status_e
_update_process_set(vs_fldt_client_file_type_mapping_t *object_info,
                    uint32_t command,
                    uint32_t expected_offset,
                    const uint8_t *request_data,
                    uint32_t request_data_sz) {
    CHECK_NOT_ZERO_RET(object_info, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(
            request_data_sz <= VS_FLDT_REQUEST_SZ_MAX, VS_CODE_ERR_TOO_SMALL_BUFFER, "Small buffer for Retry command");

    vs_fldt_update_ctx_t *update_ctx = &object_info->update_ctx;

    if (update_ctx->command != command) {
        VS_FLDT_PRINT_DEBUG(object_info->type.type, command, "_update_process_set");
    }

    update_ctx->in_progress = true;
    update_ctx->tick_cnt = 0;
    update_ctx->retry_used = 0;
    update_ctx->command = command;
    update_ctx->gateway_mac = object_info->gateway_mac;
    update_ctx->expected_offset = expected_offset;
    VS_IOT_MEMCPY(update_ctx->data, request_data, request_data_sz);
    update_ctx->data_sz = request_data_sz;
    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_update_process_retry(vs_fldt_client_file_type_mapping_t *object_info) {

    CHECK_NOT_ZERO_RET(object_info, VS_CODE_ERR_INCORRECT_ARGUMENT);
    vs_fldt_update_ctx_t *update_ctx = &object_info->update_ctx;

    update_ctx->retry_used++;

    if (update_ctx->retry_used > VS_FLDT_RETRY_MAX) {
        VS_FLDT_PRINT_DEBUG(
                object_info->type.type, update_ctx->command, "Update process has been stopped, because of retry limit");
        _update_process_reset(object_info);
        return VS_CODE_OK;
    }

    VS_FLDT_PRINT_DEBUG(object_info->type.type, update_ctx->command, "_update_process_retry");

    CHECK_RET(!vs_snap_send_request(NULL,
                                    &update_ctx->gateway_mac,
                                    VS_FLDT_SERVICE_ID,
                                    update_ctx->command,
                                    update_ctx->data,
                                    update_ctx->data_sz),
              VS_CODE_ERR_INCORRECT_SEND_REQUEST,
              "Unable to re-send FLDT request");

    return VS_CODE_OK;
}

/******************************************************************/
static vs_fldt_client_file_type_mapping_t *
_get_mapping_elem(const vs_update_file_type_t *file_type) {
    vs_fldt_client_file_type_mapping_t *file_type_info = _client_file_type_mapping;
    uint32_t id;

    for (id = 0; id < _file_type_mapping_array_size; ++id, ++file_type_info) {
        if (vs_update_equal_file_type(&file_type_info->type, file_type)) {
            return file_type_info;
        }
    }

    VS_LOG_WARNING("[FLDT] Unable to find file type specified");

    return NULL;
}

/******************************************************************/
static const char *
_filever_descr(vs_fldt_client_file_type_mapping_t *file_type_info,
               const vs_file_version_t *file_ver,
               char *file_descr,
               uint32_t descr_buff_size) {
    VS_IOT_ASSERT(file_type_info);
    return file_type_info->update_interface->describe_version(file_type_info->update_interface->storage_context,
                                                              &file_type_info->type,
                                                              file_ver,
                                                              file_descr,
                                                              descr_buff_size,
                                                              true);
}

/******************************************************************/
static const char *
_filetype_descr(vs_fldt_client_file_type_mapping_t *file_type_info, char *file_descr, uint32_t descr_buff_size) {
    VS_IOT_ASSERT(file_type_info);
    return vs_update_type_descr(&file_type_info->type, file_type_info->update_interface, file_descr, descr_buff_size);
}

/******************************************************************/
static vs_status_e
_check_download_need(const char *opcode,
                     vs_fldt_client_file_type_mapping_t *file_type_info,
                     vs_file_version_t *current_file_ver,
                     const vs_file_version_t *new_file_ver,
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

    *download = file_type_info->update_interface->file_is_newer(
            file_type_info->update_interface->storage_context, &file_type_info->type, current_file_ver, new_file_ver);

    if (*download) {
        VS_LOG_DEBUG("[FLDT:%s] Need to download new version", opcode);
    } else {
        VS_LOG_DEBUG("[FLDT:%s] No need to download new version", opcode);
    }

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_file_info_processor(const char *cmd_prefix, const vs_fldt_file_info_t *file_info) {

    const vs_file_version_t *new_file_ver = NULL;
    const vs_update_file_type_t *file_type = NULL;
    vs_fldt_gnfh_header_request_t header_request;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    bool download;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_e ret_code;

    VS_IOT_ASSERT(cmd_prefix);
    VS_IOT_ASSERT(file_info);

    new_file_ver = &file_info->type.info.version;
    file_type = &file_info->type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    VS_LOG_DEBUG("[FLDT:%s] Request from gateway about new file" FLDT_MAC_PRINT_TEMPLATE " for %s",
                 cmd_prefix,
                 FLDT_MAC_PRINT_ARG(file_info->gateway_mac),
                 _filever_descr(file_type_info, new_file_ver, file_descr, sizeof(file_descr)));

    file_type_info->gateway_mac = file_info->gateway_mac;

    STATUS_CHECK_RET(_check_download_need(
                             cmd_prefix, file_type_info, &file_type_info->cur_file_version, new_file_ver, &download),
                     "Unable to check download need");

    if (download) {

        file_type_info->prev_file_version = file_type_info->cur_file_version;
        file_type_info->cur_file_version = file_info->type.info.version;
        header_request.type = *file_type;
        header_request.type.info.version = file_info->type.info.version;

        VS_LOG_DEBUG("[FLDT] Ask file header for file %s",
                     _filever_descr(file_type_info, new_file_ver, file_descr, sizeof(file_descr)));

        // Normalize byte order
        vs_fldt_gnfh_header_request_t_encode(&header_request);

        CHECK_RET(VS_CODE_OK == _update_process_set(file_type_info,
                                                    VS_FLDT_GNFH,
                                                    0,
                                                    (const uint8_t *)&header_request,
                                                    sizeof(header_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Can't set up retry process");
        CHECK_RET(!vs_snap_send_request(NULL,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_SERVICE_ID,
                                        VS_FLDT_GNFH,
                                        (const uint8_t *)&header_request,
                                        sizeof(header_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFH\" server request");
    }

    return VS_CODE_OK;
}


/******************************************************************/
static int
vs_fldt_INFV_request_processor(const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    vs_fldt_infv_new_file_request_t *new_file = (vs_fldt_infv_new_file_request_t *)request;
    vs_status_e ret_code;

    (void)response;
    (void)response_buf_sz;
    (void)response_sz;

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_ZERO_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*new_file),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Unsupported request structure, vs_fldt_infv_new_file_request_t has been waited");

    VS_LOG_DEBUG("[FLDT:INFV] Received from " FLDT_MAC_PRINT_TEMPLATE, FLDT_MAC_PRINT_ARG(new_file->gateway_mac));
    // Normalize byte order
    vs_fldt_file_info_t_decode(new_file);

    STATUS_CHECK_RET(_file_info_processor("INFV", new_file), "Unable to process INFV request");

    return VS_CODE_OK;
}

/******************************************************************/
static int
vs_fldt_GNFH_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfh_header_response_t *file_header = (vs_fldt_gnfh_header_response_t *)response;
    vs_file_version_t *file_ver = NULL;
    vs_update_file_type_t *file_type = NULL;
    vs_fldt_gnfd_data_request_t data_request;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_e ret_code;
    bool is_need_download;

    CHECK_RET(is_ack, VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE, "wrong GNFH response");
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Normalize byte order
    vs_fldt_gnfh_header_response_t_decode(file_header);

    CHECK_NOT_ZERO_RET(file_header->file_size, VS_CODE_ERR_INCORRECT_ARGUMENT);

    file_ver = &file_header->fldt_info.type.info.version;
    file_type = &file_header->fldt_info.type;

    CHECK_RET(file_type_info = _get_mapping_elem(file_type),
              VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
              "Unregistered file type");

    STATUS_CHECK_RET(_check_download_need(
                             "GNFH", file_type_info, &file_type_info->cur_file_version, file_ver, &is_need_download),
                     "Unable to check download need");
    if (!is_need_download) {
        file_type_info->update_ctx.in_progress = false;
        VS_LOG_WARNING("[FLDT:GNFH] File [type %d] header contains an old version", file_type->type);
        return VS_CODE_OLD_VERSION;
    }

    VS_LOG_DEBUG("[FLDT:GNFH] Response file size %d bytes, %s, for file %s",
                 file_header->file_size,
                 file_header->has_footer ? "has footer" : "no footer",
                 _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));

    file_type_info->gateway_mac = file_header->fldt_info.gateway_mac;

    CHECK_RET(response_sz >= sizeof(*file_header),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response must be of vs_fldt_gnfh_header_response_t type");

    STATUS_CHECK_RET(file_type_info->update_interface->set_header(file_type_info->update_interface->storage_context,
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
    data_request.type.info.version = file_header->fldt_info.type.info.version;

    VS_LOG_DEBUG("[FLDT] Ask file data offset %d for file %s",
                 data_request.offset,
                 _filever_descr(file_type_info, &data_request.type.info.version, file_descr, sizeof(file_descr)));

    // Normalize byte order
    vs_fldt_gnfd_data_request_t_encode(&data_request);

    CHECK_RET(VS_CODE_OK == _update_process_set(file_type_info,
                                                VS_FLDT_GNFD,
                                                data_request.offset,
                                                (const uint8_t *)&data_request,
                                                sizeof(data_request)),
              VS_CODE_ERR_INCORRECT_SEND_REQUEST,
              "Can't set up retry process");

    CHECK_RET(!vs_snap_send_request(NULL,
                                    &file_type_info->gateway_mac,
                                    VS_FLDT_SERVICE_ID,
                                    VS_FLDT_GNFD,
                                    (const uint8_t *)&data_request,
                                    sizeof(data_request)),
              VS_CODE_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"GNFD\" server request");

    return VS_CODE_OK;
}

/******************************************************************/
static int
vs_fldt_GNFD_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnfd_data_response_t *file_data = (vs_fldt_gnfd_data_response_t *)response;
    vs_file_version_t *file_ver = NULL;
    vs_update_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfd_data_request_t data_request;
    vs_fldt_gnff_footer_request_t footer_request;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_e ret_code;

    CHECK_RET(is_ack, VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE, "wrong GNFD response");

    // Normalize byte order
    vs_fldt_gnfd_data_response_t_decode(file_data);

    file_ver = &file_data->type.info.version;
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

    STATUS_CHECK_RET(file_type_info->update_interface->set_data(file_type_info->update_interface->storage_context,
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
        data_request.type.info.version = file_data->type.info.version;

#if DEBUG_CHUNKS
        VS_LOG_DEBUG("[FLDT] Ask file data offset %d for file %s",
                     data_request.offset,
                     _filever_descr(file_type_info, &data_request.type.info.version, file_descr, sizeof(file_descr)));
#endif
        // Normalize byte order
        vs_fldt_gnfd_data_request_t_encode(&data_request);

        CHECK_RET(VS_CODE_OK == _update_process_set(file_type_info,
                                                    VS_FLDT_GNFD,
                                                    data_request.offset,
                                                    (const uint8_t *)&data_request,
                                                    sizeof(data_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Can't set up retry process");

        CHECK_RET(!vs_snap_send_request(NULL,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_SERVICE_ID,
                                        VS_FLDT_GNFD,
                                        (const uint8_t *)&data_request,
                                        sizeof(data_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFD\" server request");

    } else {

        // Load footer

        footer_request.type = *file_type;
        footer_request.type.info.version = file_data->type.info.version;

        // Normalize byte order
        vs_fldt_gnff_footer_request_t_encode(&footer_request);

        CHECK_RET(VS_CODE_OK == _update_process_set(file_type_info,
                                                    VS_FLDT_GNFF,
                                                    0,
                                                    (const uint8_t *)&footer_request,
                                                    sizeof(footer_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Can't set up retry process");

        CHECK_RET(!vs_snap_send_request(NULL,
                                        &file_type_info->gateway_mac,
                                        VS_FLDT_SERVICE_ID,
                                        VS_FLDT_GNFF,
                                        (const uint8_t *)&footer_request,
                                        sizeof(footer_request)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"GNFF\" server request");
    }

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
vs_fldt_ask_file_type_info(const char *file_type_descr,
                           vs_fldt_gnfh_header_request_t *gnfh_request,
                           vs_fldt_client_file_type_mapping_t *file_type_info) {
    CHECK_NOT_ZERO_RET(gnfh_request, VS_CODE_ERR_INCORRECT_ARGUMENT);

    VS_LOG_DEBUG("[FLDT] Ask file type information for file type %s", file_type_descr);

    vs_fldt_gnfh_header_request_t_encode(gnfh_request);
    file_type_info->gateway_mac = *vs_snap_broadcast_mac();

    CHECK_RET(VS_CODE_OK ==
                      _update_process_set(
                              file_type_info, VS_FLDT_GNFH, 0, (const uint8_t *)gnfh_request, sizeof(*gnfh_request)),
              VS_CODE_ERR_INCORRECT_SEND_REQUEST,
              "Can't set up retry process");
    CHECK_RET(!vs_snap_send_request(NULL,
                                    &file_type_info->gateway_mac,
                                    VS_FLDT_SERVICE_ID,
                                    VS_FLDT_GNFH,
                                    (const uint8_t *)gnfh_request,
                                    sizeof(*gnfh_request)),
              VS_CODE_ERR_INCORRECT_SEND_REQUEST,
              "Unable to send FLDT \"GFTI\" server request");


    return VS_CODE_OK;
}

/******************************************************************/
static int
vs_fldt_GNFF_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz) {
    vs_fldt_gnff_footer_response_t *file_footer = (vs_fldt_gnff_footer_response_t *)response;
    vs_file_version_t *file_ver = NULL;
    vs_update_file_type_t *file_type = NULL;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    bool successfully_updated;
    vs_status_e ret_code;

    CHECK_RET(is_ack, VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE, "wrong GNFF response");

    // Normalize byte order
    vs_fldt_gnff_footer_response_t_decode(file_footer);

    file_ver = &file_footer->type.info.version;
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

    ret_code = file_type_info->update_interface->set_footer(file_type_info->update_interface->storage_context,
                                                            file_type,
                                                            file_type_info->file_header,
                                                            file_footer->footer_data,
                                                            file_footer->footer_size);
    successfully_updated = (ret_code == VS_CODE_OK);

    if (!successfully_updated) {
        VS_LOG_ERROR("Error while processing footer for file %s",
                     _filever_descr(file_type_info, file_ver, file_descr, sizeof(file_descr)));
    }

    // Stop retries
    file_type_info->update_ctx.in_progress = !successfully_updated;

    _got_file_callback(file_type,
                       &file_type_info->prev_file_version,
                       file_ver,
                       file_type_info->update_interface,
                       &file_type_info->gateway_mac,
                       successfully_updated);

    return VS_CODE_OK;
}

/******************************************************************/
vs_status_e
vs_fldt_client_add_file_type(const vs_update_file_type_t *file_type, vs_update_interface_t *update_interface) {
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    vs_fldt_gnfh_header_request_t gnfh_request;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_e ret_code;
    uint32_t header_size;

    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_INCORRECT_ARGUMENT);

    file_type_info = _get_mapping_elem(file_type);

    if (!file_type_info) {
        VS_IOT_ASSERT(_file_type_mapping_array_size < (CLIENT_FILE_TYPE_ARRAY_SIZE - 1));
        CHECK_RET(_file_type_mapping_array_size < (CLIENT_FILE_TYPE_ARRAY_SIZE - 1),
                  VS_CODE_ERR_NO_MEMORY,
                  "[FLDT] Can't add new file type. Array is full");
        file_type_info = &_client_file_type_mapping[_file_type_mapping_array_size++];
        VS_LOG_DEBUG("[FLDT] File type was not initialized, add new entry. Array size = %d",
                     _file_type_mapping_array_size);
        VS_IOT_MEMSET(file_type_info, 0, sizeof(*file_type_info));
    } else {
        VS_LOG_DEBUG("[FLDT] File type is initialized present, update");
    }

    _update_process_reset(file_type_info);

    file_type_info->type = *file_type;
    file_type_info->update_interface = update_interface;

    VS_LOG_DEBUG("[FLDT] Update file type %s", _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

    STATUS_CHECK_RET(file_type_info->update_interface->get_header_size(
                             file_type_info->update_interface->storage_context, &file_type_info->type, &header_size),
                     "Unable to calculate header size for file type %s",
                     file_descr);
    if (header_size) {
        file_type_info->file_header = VS_IOT_MALLOC(header_size);
    }

    file_type_info->file_size = 0;

    ret_code = file_type_info->update_interface->get_header(file_type_info->update_interface->storage_context,
                                                            &file_type_info->type,
                                                            file_type_info->file_header, // Version is here
                                                            header_size,
                                                            &header_size);
    if (VS_CODE_OK == ret_code) {
        VS_LOG_INFO("[FLDT] Current file version : %s",
                    _filever_descr(file_type_info, &file_type_info->type.info.version, file_descr, sizeof(file_descr)));
        VS_IOT_MEMCPY(&file_type_info->cur_file_version,
                      &file_type_info->type.info.version,
                      sizeof(file_type_info->type.info.version));
    } else {
        VS_LOG_WARNING("[FLDT] File type was not found by Update library");
        VS_IOT_FREE(file_type_info->file_header);
        file_type_info->file_header = NULL;
    }

    VS_IOT_MEMSET(&file_type_info->gateway_mac, 0, sizeof(file_type_info->gateway_mac));

    gnfh_request.type = *file_type;
    STATUS_CHECK_RET(vs_fldt_ask_file_type_info(file_descr, &gnfh_request, file_type_info),
                     "Unable to ask current file information");

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
_fldt_destroy_client(void) {
    uint32_t id;
    vs_fldt_client_file_type_mapping_t *file_type_mapping = _client_file_type_mapping;

    for (id = 0; id < _file_type_mapping_array_size; ++id, ++file_type_mapping) {
        file_type_mapping->update_interface->free_item(file_type_mapping->update_interface->storage_context,
                                                       &file_type_mapping->type);
        VS_IOT_FREE(file_type_mapping->file_header);
    }

    _file_type_mapping_array_size = 0;

    return VS_CODE_OK;
}

/******************************************************************************/
static int
_fldt_client_request_processor(const struct vs_netif_t *netif,
                               vs_snap_element_t element_id,
                               const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {
    (void)netif;

    *response_sz = 0;

    switch (element_id) {

    case VS_FLDT_INFV:
        return vs_fldt_INFV_request_processor(request, request_sz, response, response_buf_sz, response_sz);


    case VS_FLDT_GNFH:
    case VS_FLDT_GNFD:
    case VS_FLDT_GNFF:
        return VS_CODE_COMMAND_NO_RESPONSE;

    default:
        VS_LOG_ERROR("Unsupported FLDT command");
        VS_IOT_ASSERT(false);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
static int
_fldt_client_response_processor(const struct vs_netif_t *netif,
                                vs_snap_element_t element_id,
                                bool is_ack,
                                const uint8_t *response,
                                const uint16_t response_sz) {
    (void)netif;

    switch (element_id) {

    case VS_FLDT_INFV:
        if (!is_ack) {
            VS_LOG_WARNING("GINF Received response packet with is_ack == false");
        }
        return VS_CODE_COMMAND_NO_RESPONSE;

    case VS_FLDT_GNFH:
        return vs_fldt_GNFH_response_processor(is_ack, response, response_sz);

    case VS_FLDT_GNFD:
        return vs_fldt_GNFD_response_processor(is_ack, response, response_sz);

    case VS_FLDT_GNFF:
        return vs_fldt_GNFF_response_processor(is_ack, response, response_sz);


    default:
        VS_LOG_ERROR("Unsupported FLDT command");
        VS_IOT_ASSERT(false);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
static int
_fldt_client_periodical_processor(void) {
    vs_fldt_client_file_type_mapping_t *file_type_info = _client_file_type_mapping;
    vs_fldt_update_ctx_t *_update_ctx;
    uint32_t id;

    for (id = 0; id < _file_type_mapping_array_size; ++id, ++file_type_info) {
        _update_ctx = &file_type_info->update_ctx;
        if (_update_ctx->in_progress) {
            _update_ctx->tick_cnt++;
            if (_update_ctx->tick_cnt > VS_FLDT_WAIT_MAX) {
                _update_process_retry(file_type_info);
            }
        }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_fldt_client(vs_fldt_got_file got_file_callback) {

    VS_IOT_ASSERT(got_file_callback);
    VS_IOT_ASSERT(CLIENT_FILE_TYPE_ARRAY_SIZE);

    _fldt_client.user_data = 0;
    _fldt_client.id = VS_FLDT_SERVICE_ID;
    _fldt_client.request_process = _fldt_client_request_processor;
    _fldt_client.response_process = _fldt_client_response_processor;
    _fldt_client.periodical_process = _fldt_client_periodical_processor;
    _fldt_client.deinit = _fldt_destroy_client;

    _got_file_callback = got_file_callback;

    return &_fldt_client;
}

/******************************************************************************/
vs_status_e
vs_fldt_client_request_all_files(void) {
    size_t id;
    vs_fldt_gnfh_header_request_t gnfh_request;
    vs_fldt_client_file_type_mapping_t *file_type_info = NULL;
    char file_descr[FLDT_FILEVER_BUF];
    vs_status_e ret_code;

    VS_LOG_DEBUG("[FLDT] Request all registered file types update");

    if (!_file_type_mapping_array_size) {
        VS_LOG_WARNING("[FLDT] No registered file types");
        return VS_CODE_OK;
    }

    for (id = 0; id < _file_type_mapping_array_size; ++id) {
        file_type_info = &_client_file_type_mapping[id];

        VS_LOG_DEBUG("[FLDT] Request file type %s", _filetype_descr(file_type_info, file_descr, sizeof(file_descr)));

        gnfh_request.type = file_type_info->type;

        STATUS_CHECK_RET(vs_fldt_ask_file_type_info(file_descr, &gnfh_request, file_type_info),
                         "Unable to ask current file information");
    }

    return VS_CODE_OK;
}

#endif // FLDT_CLIENT