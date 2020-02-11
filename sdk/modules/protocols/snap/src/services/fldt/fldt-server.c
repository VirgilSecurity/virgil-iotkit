//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#if FLDT_SERVER

#include <virgil/iot/protocols/snap/fldt/fldt-server.h>
#include <virgil/iot/protocols/snap/fldt/fldt-private.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/macros/macros.h>
#include <endian-config.h>
#include <virgil/iot/update/update.h>

// TODO : This setting might be moved to some config
#define SERVER_FILE_TYPE_ARRAY_SIZE (10)

static vs_snap_service_t _fldt_server = {0};

typedef struct {
    vs_update_file_type_t type;
    vs_update_interface_t *update_context;
    vs_file_version_t current_version;
    void *file_header;
    uint32_t file_size;
} vs_fldt_server_file_type_mapping_t;

static uint32_t _file_type_mapping_array_size = 0;
static vs_fldt_server_file_type_mapping_t _server_file_type_mapping[SERVER_FILE_TYPE_ARRAY_SIZE];
static vs_fldt_server_add_filetype_cb _add_filetype_callback = NULL;
static vs_mac_addr_t _gateway_mac;

static vs_status_e
_fldt_destroy_server(void);

/******************************************************************/
static vs_fldt_server_file_type_mapping_t *
_get_mapping_elem(const vs_update_file_type_t *file_type) {
    vs_fldt_server_file_type_mapping_t *file_type_info = _server_file_type_mapping;
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
static vs_status_e
_new_mapping_element(vs_fldt_server_file_type_mapping_t **file_element_to_add) {
    VS_IOT_ASSERT(_file_type_mapping_array_size < (SERVER_FILE_TYPE_ARRAY_SIZE - 1));
    CHECK_RET(_file_type_mapping_array_size < (SERVER_FILE_TYPE_ARRAY_SIZE - 1),
              VS_CODE_ERR_NO_MEMORY,
              "[FLDT] Can't add new file type. Array is full");
    *file_element_to_add = &_server_file_type_mapping[_file_type_mapping_array_size++];
    VS_LOG_DEBUG("[FLDT] File type was not initialized, add new entry. Array size = %d", _file_type_mapping_array_size);
    VS_IOT_MEMSET(*file_element_to_add, 0, sizeof(vs_fldt_server_file_type_mapping_t));
    return VS_CODE_OK;
}

/******************************************************************/
static void
_delete_mapping_element(vs_fldt_server_file_type_mapping_t *file_element_to_delete) {
    vs_fldt_server_file_type_mapping_t *file_type_info = _server_file_type_mapping;
    uint32_t id;
    bool found = false;
    if (0 == _file_type_mapping_array_size) {
        return;
    }

    for (id = 0; id < _file_type_mapping_array_size; ++id, ++file_type_info) {
        if (!found) {
            if (file_element_to_delete == file_type_info) {
                if (file_element_to_delete->update_context && file_element_to_delete->update_context->free_item) {
                    file_element_to_delete->update_context->free_item(
                            file_element_to_delete->update_context->storage_context, &file_element_to_delete->type);
                }
                if (file_element_to_delete->file_header) {
                    VS_LOG_DEBUG("Delete file header : %s",
                                 VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element_to_delete->type));
                    VS_IOT_FREE(file_element_to_delete->file_header);
                    file_element_to_delete->file_header = NULL;
                }
                found = true;
            }
        } else {
            _server_file_type_mapping[id - 1] = *file_type_info;
            VS_IOT_MEMSET(file_type_info, 0, sizeof(vs_fldt_server_file_type_mapping_t));
        }
    }

    if (found) {
        _file_type_mapping_array_size--;
    }
}

/******************************************************************/
static vs_status_e
_update_object_info(const vs_update_file_type_t *file_type,
                    vs_update_interface_t *update_context,
                    vs_fldt_server_file_type_mapping_t *file_element,
                    vs_update_file_type_t *file_type_for_object) {
    vs_status_e ret_code;
    file_element->type = *file_type;
    file_element->update_context = update_context;
    uint32_t file_header_size;

    ret_code = update_context->get_header_size(update_context->storage_context, &file_element->type, &file_header_size);
    if (VS_CODE_OK != ret_code || !file_header_size) {
        VS_LOG_ERROR("Unable to get header size for file type %s", VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element->type));
        ret_code = (VS_CODE_OK == ret_code) ? VS_CODE_ERR_VERIFY : ret_code;
        goto terminate;
    }

    if (file_element->file_header) {
        VS_LOG_DEBUG("Free file header before malloc: %s", VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element->type));
        VS_IOT_FREE(file_element->file_header);
    }

    VS_LOG_DEBUG("Malloc file header : %s", VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element->type));
    file_element->file_header = VS_IOT_MALLOC(file_header_size);

    ret_code = update_context->get_header(update_context->storage_context,
                                          &file_element->type,
                                          file_element->file_header,
                                          file_header_size,
                                          &file_header_size);
    STATUS_CHECK(
            ret_code, "Unable to get header for file type %s", VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element->type));

    ret_code = update_context->verify_object(update_context->storage_context, &file_element->type);
    STATUS_CHECK(ret_code, "Unable to verify object type %s", VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element->type));

    ret_code = update_context->get_file_size(
            update_context->storage_context, &file_element->type, file_element->file_header, &file_element->file_size);
    STATUS_CHECK(ret_code,
                 "Unable to get header size for file type %s",
                 VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element->type));

    file_element->current_version = file_element->type.info.version;

    VS_LOG_DEBUG("[FLDT] Update file %s", VS_UPDATE_FILE_VERSION_STR_STATIC(&file_element->current_version));

    VS_IOT_MEMSET(file_type_for_object, 0, sizeof(*file_type_for_object));


    file_type_for_object->type = file_type->type;
    VS_IOT_MEMCPY(file_type_for_object->info.manufacture_id,
                  file_type->info.manufacture_id,
                  sizeof(file_type->info.manufacture_id));
    VS_IOT_MEMCPY(
            file_type_for_object->info.device_type, file_type->info.device_type, sizeof(file_type->info.device_type));
    file_type_for_object->info.version = file_element->current_version;

    return VS_CODE_OK;

terminate:
    if (file_element->file_header) {
        VS_LOG_DEBUG("Free file header : %s", VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element->type));
        VS_IOT_FREE(file_element->file_header);
        file_element->file_header = NULL;
    }
    VS_IOT_MEMSET(file_element, 0, sizeof(*file_element));
    return ret_code;
}

/*************************************************************************/
static bool
_file_is_newer(const vs_file_version_t *available_file, const vs_file_version_t *new_file) {
    return (VS_CODE_OK == vs_update_compare_version(new_file, available_file));
}

/******************************************************************/
static vs_status_e
_get_object_info_by_type(const vs_update_file_type_t *requested_file_type,
                         vs_fldt_server_file_type_mapping_t **element_type_info_ptr,
                         vs_update_file_type_t *file_type_for_object) {
    vs_status_e ret_code;
    vs_update_interface_t *update_context;
    vs_fldt_server_file_type_mapping_t *file_element = NULL;
    *element_type_info_ptr = NULL;

    file_element = _get_mapping_elem(requested_file_type);

    if (file_element && _file_is_newer(&file_element->type.info.version, &requested_file_type->info.version)) {
        ret_code = _update_object_info(
                requested_file_type, file_element->update_context, file_element, file_type_for_object);
        if (VS_CODE_OK != ret_code) {
            _delete_mapping_element(file_element);
            return VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE;
        }
    }

    if (!file_element) {

        CHECK_RET(_add_filetype_callback,
                  VS_CODE_ERR_NO_CALLBACK,
                  "No has add_filetype_callback for file type [%d]",
                  requested_file_type->type);

        STATUS_CHECK_RET(_add_filetype_callback(requested_file_type, &update_context),
                         "Unable to add file type [%d]",
                         requested_file_type->type);

        STATUS_CHECK_RET(_new_mapping_element(&file_element), "");

        ret_code = _update_object_info(requested_file_type, update_context, file_element, file_type_for_object);
        if (VS_CODE_OK != ret_code) {
            _delete_mapping_element(file_element);
            return VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE;
        }
    } else {
        VS_IOT_MEMCPY(file_type_for_object, &file_element->type, sizeof(file_element->type));
    }

    *element_type_info_ptr = file_element;
    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
vs_fldt_GNFH_request_processor(const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    vs_fldt_gnfh_header_request_t *header_request = (vs_fldt_gnfh_header_request_t *)request;
    const vs_update_file_type_t *requested_file_type = NULL;
    vs_fldt_server_file_type_mapping_t *file_element = NULL;
    vs_fldt_gnfh_header_response_t *header_response = (vs_fldt_gnfh_header_response_t *)response;
    uint32_t header_size;
    vs_status_e ret_code;
    bool has_footer;

    *response_sz = 0;
    VS_IOT_MEMSET(header_response, 0, sizeof(*header_response));

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*header_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnfh_header_request_t type");
    CHECK_RET(response_buf_sz > sizeof(*header_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfh_header_response_t structure");

    // Normalize byte order
    vs_fldt_gnfh_header_request_t_decode(header_request);

    requested_file_type = &header_request->type;

    STATUS_CHECK_RET(_get_object_info_by_type(requested_file_type, &file_element, &header_response->fldt_info.type),
                     "Unable to get information for file %s",
                     VS_UPDATE_FILE_TYPE_STR_STATIC(requested_file_type));
    header_response->fldt_info.gateway_mac = _gateway_mac;

    VS_LOG_DEBUG("[FLDT:GNFH] Header request for %s", VS_UPDATE_FILE_TYPE_STR_STATIC(&header_request->type));

    header_response->file_size = file_element->file_size;

    STATUS_CHECK_RET(file_element->update_context->has_footer(
                             file_element->update_context->storage_context, &file_element->type, &has_footer),
                     "[FLDT:GNFH] Unable to check that there is footer for file %s",
                     VS_UPDATE_FILE_TYPE_STR_STATIC(&header_response->fldt_info.type));

    header_response->has_footer = (has_footer != 0);

    STATUS_CHECK_RET(file_element->update_context->get_header_size(
                             file_element->update_context->storage_context, &file_element->type, &header_size),
                     "Unable to get header size for file %s",
                     VS_UPDATE_FILE_TYPE_STR_STATIC(&file_element->type));
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
        VS_IOT_MEMCPY(header_response->header_data, file_element->file_header, header_size);
        *response_sz = sizeof(*header_response) + header_response->header_size;
    }

    VS_LOG_DEBUG("[FLDT:GNFH] Header size %d, file size %d bytes, %s",
                 header_response->header_size,
                 header_response->file_size,
                 header_response->has_footer ? "has footer" : "no footer");

    // Normalize byte order
    vs_fldt_gnfh_header_response_t_encode(header_response);

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
vs_fldt_GNFD_request_processor(const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    vs_fldt_gnfd_data_request_t *data_request = (vs_fldt_gnfd_data_request_t *)request;

    const vs_update_file_type_t *requested_file_type = NULL;
    vs_fldt_server_file_type_mapping_t *existing_file_element = NULL;
    vs_fldt_gnfd_data_response_t *data_response = (vs_fldt_gnfd_data_response_t *)response;
    static const uint32_t DATA_SZ = 512;
    ssize_t max_data_size_to_read;
    uint32_t data_size_read;
    vs_status_e ret_code;
    uint32_t cur_offset;
    uint32_t next_offset;

    *response_sz = 0;
    VS_IOT_MEMSET(data_response, 0, sizeof(*data_response));

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Normalize byte order
    vs_fldt_gnfd_data_request_t_decode(data_request);

    CHECK_RET(request_sz == sizeof(*data_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnfd_data_request_t type");
    CHECK_RET(response_buf_sz > sizeof(*data_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnfd_data_response_t structure");

    requested_file_type = &data_request->type;
    STATUS_CHECK_RET(_get_object_info_by_type(requested_file_type, &existing_file_element, &data_response->type),
                     "Unable to get information for file %s",
                     VS_UPDATE_FILE_TYPE_STR_STATIC(requested_file_type));

    CHECK_RET(data_request->offset < existing_file_element->file_size,
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request's data offset %d is not inside file data size %d",
              data_request->offset,
              existing_file_element->file_size);

    data_response->type.info.version = data_request->type.info.version;
    data_response->type = data_request->type;
    data_response->offset = data_request->offset;

    max_data_size_to_read = response_buf_sz - sizeof(*data_response);
    if (max_data_size_to_read > DATA_SZ) {
        max_data_size_to_read = DATA_SZ;
    }
    cur_offset = data_request->offset;

    STATUS_CHECK_RET(
            existing_file_element->update_context->get_data(existing_file_element->update_context->storage_context,
                                                            &existing_file_element->type,
                                                            existing_file_element->file_header,
                                                            data_response->data,
                                                            max_data_size_to_read,
                                                            &data_size_read,
                                                            cur_offset),
            "Unable to read %d (%Xh) data items starting from offset %d (%Xh) data items for file %s",
            max_data_size_to_read,
            cur_offset,
            VS_UPDATE_FILE_TYPE_STR_STATIC(&existing_file_element->type));

    data_response->data_size = data_size_read;

    STATUS_CHECK_RET(existing_file_element->update_context->inc_data_offset(
                             existing_file_element->update_context->storage_context,
                             &existing_file_element->type,
                             cur_offset,
                             data_size_read,
                             &next_offset),
                     "Unable to retrieve offset for file %s",
                     VS_UPDATE_FILE_TYPE_STR_STATIC(&existing_file_element->type));

    data_response->next_offset = next_offset;

    *response_sz = sizeof(vs_fldt_gnfd_data_response_t) + data_response->data_size;

    // Normalize byte order
    vs_fldt_gnfd_data_response_t_encode(data_response);

    return VS_CODE_OK;
}

/******************************************************************/
static vs_status_e
vs_fldt_GNFF_request_processor(const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    vs_fldt_gnff_footer_request_t *footer_request = (vs_fldt_gnff_footer_request_t *)request;
    const vs_file_version_t *file_ver = NULL;
    vs_fldt_server_file_type_mapping_t *existing_file_element = NULL;
    vs_fldt_gnff_footer_response_t *footer_response = (vs_fldt_gnff_footer_response_t *)response;
    static const uint16_t DATA_SZ = 512;
    uint32_t data_size;
    vs_status_e ret_code;
    bool has_footer;

    *response_sz = 0;
    VS_IOT_MEMSET(footer_response, 0, sizeof(*footer_response));

    CHECK_NOT_ZERO_RET(request, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(request_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(request_sz == sizeof(*footer_request),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Request buffer must be of vs_fldt_gnff_footer_request_t type");
    CHECK_RET(response_buf_sz > sizeof(*footer_response),
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "Response buffer must have enough size to store vs_fldt_gnff_footer_response_t structure");

    // Normalize byte order
    vs_fldt_gnff_footer_request_t_decode(footer_request);

    file_ver = &footer_request->type.info.version;

    STATUS_CHECK_RET(_get_object_info_by_type(&footer_request->type, &existing_file_element, &footer_response->type),
                     "Unable to get information for file %s",
                     VS_UPDATE_FILE_TYPE_STR_STATIC(&footer_request->type));

    VS_LOG_DEBUG("[FLDT:GNFF] Footer request for %s %s",
                 VS_UPDATE_FILE_TYPE_STR_STATIC(&existing_file_element->type),
                 VS_UPDATE_FILE_VERSION_STR_STATIC(file_ver));

    STATUS_CHECK_RET(
            existing_file_element->update_context->has_footer(
                    existing_file_element->update_context->storage_context, &existing_file_element->type, &has_footer),
            "Unable to check that there is footer for %s",
            VS_UPDATE_FILE_TYPE_STR_STATIC(&existing_file_element->type));

    CHECK_RET(has_footer,
              VS_CODE_ERR_INCORRECT_ARGUMENT,
              "There is no footer for %s",
              VS_UPDATE_FILE_TYPE_STR_STATIC(&existing_file_element->type));

    footer_response->type = footer_request->type;
    footer_response->type.info.version = footer_request->type.info.version;

    data_size = response_buf_sz - sizeof(vs_fldt_gnff_footer_response_t);
    if (data_size > DATA_SZ) {
        data_size = DATA_SZ;
    }

    STATUS_CHECK_RET(
            existing_file_element->update_context->get_footer(existing_file_element->update_context->storage_context,
                                                              &existing_file_element->type,
                                                              existing_file_element->file_header,
                                                              footer_response->footer_data,
                                                              data_size,
                                                              &data_size),
            "Unable to read %d (%Xh) footer data items for file %s",
            data_size,
            VS_UPDATE_FILE_TYPE_STR_STATIC(&existing_file_element->type));

    footer_response->footer_size = data_size;

    *response_sz = sizeof(vs_fldt_gnff_footer_response_t) + footer_response->footer_size;

    // Normalize byte order
    vs_fldt_gnff_footer_response_t_encode(footer_response);

    return VS_CODE_OK;
}

/******************************************************************/
vs_status_e
vs_fldt_server_add_file_type(const vs_update_file_type_t *file_type,
                             vs_update_interface_t *update_context,
                             bool broadcast_file_info) {
    vs_fldt_server_file_type_mapping_t *existing_file_element = NULL;
    vs_fldt_server_file_type_mapping_t file_element_to_add;
    char type_str[VS_UPDATE_DEFAULT_DESC_BUF_SZ];
    char version_str[VS_UPDATE_DEFAULT_DESC_BUF_SZ];
    vs_fldt_file_info_t new_file;
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(file_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(update_context, VS_CODE_ERR_NULLPTR_ARGUMENT);
    VS_IOT_MEMSET(&file_element_to_add, 0, sizeof(file_element_to_add));

    STATUS_CHECK_RET(_update_object_info(file_type, update_context, &file_element_to_add, &new_file.type),
                     "[FLDT] Unable to update object info");

    existing_file_element = _get_mapping_elem(file_type);

    if (existing_file_element) {
        _delete_mapping_element(existing_file_element);
        VS_LOG_DEBUG("[FLDT] File type is initialized and present, update it");
    }
    STATUS_CHECK_RET(_new_mapping_element(&existing_file_element), "[FLDT] Error to create new mapping element");

    *existing_file_element = file_element_to_add;

    new_file.gateway_mac = _gateway_mac;

    if (broadcast_file_info) {
        VS_LOG_DEBUG(
                "[FLDT] Broadcast new file information : %s %s",
                vs_update_file_type_str(&file_element_to_add.type, type_str, sizeof(type_str)),
                vs_update_file_version_str(&file_element_to_add.current_version, version_str, sizeof(version_str)));

        // Normalize byte order
        vs_fldt_file_info_t_encode(&new_file);
        CHECK_RET(!vs_snap_send_request(vs_snap_netif_routing(),
                                        vs_snap_broadcast_mac(),
                                        VS_FLDT_SERVICE_ID,
                                        VS_FLDT_INFV,
                                        (const uint8_t *)&new_file,
                                        sizeof(new_file)),
                  VS_CODE_ERR_INCORRECT_SEND_REQUEST,
                  "Unable to send FLDT \"INFV\" broadcast request");
    }

    return VS_CODE_OK;
}

/******************************************************************/
static void
_init_server(const vs_mac_addr_t *gateway_mac, vs_fldt_server_add_filetype_cb add_filetype) {

    CHECK_NOT_ZERO(add_filetype);

    _fldt_destroy_server();

    _gateway_mac = *gateway_mac;
    _add_filetype_callback = add_filetype;

terminate:;
}

/******************************************************************/
static vs_status_e
_fldt_destroy_server(void) {
    uint32_t id;
    char type_str[VS_UPDATE_DEFAULT_DESC_BUF_SZ];
    vs_fldt_server_file_type_mapping_t *file_type_mapping = _server_file_type_mapping;

    VS_LOG_DEBUG("_fldt_destroy_server");
    for (id = 0; id < _file_type_mapping_array_size; ++id, ++file_type_mapping) {
        file_type_mapping->update_context->free_item(file_type_mapping->update_context->storage_context,
                                                     &file_type_mapping->type);
        if (file_type_mapping->file_header) {
            VS_LOG_DEBUG("Destroy file header : %s",
                         vs_update_file_type_str(&file_type_mapping->type, type_str, sizeof(type_str)));
            VS_IOT_FREE(file_type_mapping->file_header);
            file_type_mapping->file_header = NULL;
        }
    }

    _file_type_mapping_array_size = 0;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_fldt_server_request_processor(const struct vs_netif_t *netif,
                               vs_snap_element_t element_id,
                               const uint8_t *request,
                               const uint16_t request_sz,
                               uint8_t *response,
                               const uint16_t response_buf_sz,
                               uint16_t *response_sz) {

    *response_sz = 0;

    switch (element_id) {

    case VS_FLDT_INFV:
        return VS_CODE_COMMAND_NO_RESPONSE;

    case VS_FLDT_GNFH:
        return vs_fldt_GNFH_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GNFD:
        return vs_fldt_GNFD_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GNFF:
        return vs_fldt_GNFF_request_processor(request, request_sz, response, response_buf_sz, response_sz);

    default:
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
static vs_status_e
_fldt_server_response_processor(const struct vs_netif_t *netif,
                                vs_snap_element_t element_id,
                                bool is_ack,
                                const uint8_t *response,
                                const uint16_t response_sz) {

    if (!is_ack) {
        VS_LOG_WARNING("Received response %08x packet with is_ack == false", element_id);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }

    switch (element_id) {

    case VS_FLDT_INFV:
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
const vs_snap_service_t *
vs_snap_fldt_server(const vs_mac_addr_t *gateway_mac, vs_fldt_server_add_filetype_cb add_filetype) {

    VS_IOT_ASSERT(SERVER_FILE_TYPE_ARRAY_SIZE);
    _fldt_server.user_data = 0;
    _fldt_server.id = VS_FLDT_SERVICE_ID;
    _fldt_server.request_process = _fldt_server_request_processor;
    _fldt_server.response_process = _fldt_server_response_processor;
    _fldt_server.periodical_process = NULL;
    _fldt_server.deinit = _fldt_destroy_server;

    _init_server(gateway_mac, add_filetype);

    return &_fldt_server;
}

/******************************************************************************/

#endif // FLDT_SERVER
