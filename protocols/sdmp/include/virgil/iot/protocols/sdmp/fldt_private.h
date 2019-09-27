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

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_FLDT_PRIVATE_H
#define VS_SECURITY_SDK_SDMP_SERVICES_FLDT_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/macros/macros.h>

#define VS_FLDT_SERVICE_ID (HTONL_IN_COMPILE_TIME('FLDT'))

//
//  Internal structures
//

// TODO : need to implement storage context
// Storage context
typedef void *vs_storage_hal_ctx_t;

typedef struct {
    //    vs_storage_hal_ctx_t storage_ctx;
    //    vs_secbox_save_hal_t save;
    //    vs_secbox_load_hal_t load;
    //    vs_storage_deinit_t deinit;
    //    vs_secbox_del_hal_t del;
    //    size_t file_sz_limit;
} vs_fldt_storage_ctx_t;

#define FLDT_FILEVER_BUF (196)         // buffer for vs_fldt_file_version_descr
#define FLDT_FILE_TYPE_ADD_INFO_SZ (4) // vs_fldt_file_type_t.add_info field size
#define FLDT_FILE_SPEC_INFO_SZ (64)    // vs_fldt_infv_new_file_request_t.file_specific_info field size

#define FLDT_GATEWAY_TEMPLATE "%x:%x:%x:%x:%x:%x"
#define FLDT_GATEWAY_ARG(MAC_ADDR)                                                                                     \
    (MAC_ADDR).bytes[0], (MAC_ADDR).bytes[1], (MAC_ADDR).bytes[2], (MAC_ADDR).bytes[3], (MAC_ADDR).bytes[4],           \
            (MAC_ADDR).bytes[5]

typedef struct __attribute__((__packed__)) {
    uint16_t file_type_id; // = vs_update_file_type_id_t
    uint8_t add_info[32];  // = vs_fldt_fw_add_info_t for VS_UPDATE_FIRMWARE
} vs_fldt_file_type_t;

typedef struct __attribute__((__packed__)) {
    uint8_t manufacture_id[16];
    uint8_t device_type[4];
} vs_fldt_fw_add_info_t;

// File version
typedef struct __attribute__((__packed__)) {
    union {
        struct {
            uint8_t major;
            uint8_t minor;
            uint8_t patch;
            uint8_t dev_milestone;
            uint8_t dev_build;
            uint32_t timestamp; // the number of seconds elapsed since January 1, 2015 UTC
        } fw_ver;

        uint16_t tl_ver;
    };
    vs_fldt_file_type_t file_type;
} vs_fldt_file_version_t;

// Return codes
typedef enum {
    VS_FLDT_ERR_OK = 0,
    VS_FLDT_ERR_INCORRECT_ARGUMENT = -1,
    VS_FLDT_ERR_UNSUPPORTED_PARAMETER = -2,
    VS_FLDT_ERR_NO_CALLBACK = -3,
    VS_FLDT_ERR_UNREGISTERED_MAPPING_TYPE = -4,
    VS_FLDT_ERR_INCORRECT_SEND_REQUEST = -5,
    VS_FLDT_ERR_NO_MEMORY = -6,
    VS_FDTL_ERR_AMBIGUOUS_INIT_CALL = -7
} vs_fldt_ret_code_e;

// Commands
// mute "error: multi-character character constant" message
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
typedef enum {
    VS_FLDT_INFV = HTONL_IN_COMPILE_TIME('INFV'), /* Inform New File Version */
    VS_FLDT_GFTI = HTONL_IN_COMPILE_TIME('GFTI'), /* Get File Type Information */
    VS_FLDT_GNFH = HTONL_IN_COMPILE_TIME('GNFH'), /* Get New File Header */
    VS_FLDT_GNFD = HTONL_IN_COMPILE_TIME('GNFD'), /* Get New File Data */
    VS_FLDT_GNFF = HTONL_IN_COMPILE_TIME('GNFF'), /* Get New File Footer */
} vs_sdmp_fldt_element_e;
#pragma GCC diagnostic pop

// Get Service descriptor

// "Inform New File Version"
typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
    vs_mac_addr_t gateway_mac;
    // TODO : is it necessary???
    uint8_t file_specific_info[FLDT_FILE_SPEC_INFO_SZ];
} vs_fldt_infv_new_file_request_t;

typedef void vs_fldt_infv_new_file_response_t;

// "Get File Type Information"
typedef struct __attribute__((__packed__)) {
    vs_fldt_file_type_t file_type;
} vs_fldt_gfti_fileinfo_request_t;

typedef vs_fldt_infv_new_file_request_t vs_fldt_gfti_fileinfo_response_t;

// "Get New File Header"
typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
} vs_fldt_gnfh_header_request_t;

typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
    uint32_t file_size;
    uint8_t has_footer;
    uint16_t header_size;
    uint8_t header_data[];
} vs_fldt_gnfh_header_response_t;

// "Get New File Data"
typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
    uint32_t offset;
} vs_fldt_gnfd_data_request_t;

typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
    uint32_t offset;
    uint16_t data_size;
    uint8_t data[];
} vs_fldt_gnfd_data_response_t;

// "Get New File Footer"
typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
} vs_fldt_gnff_footer_request_t;

typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
    uint16_t footer_size;
    uint8_t footer_data[];
} vs_fldt_gnff_footer_response_t;

// Utilities
#define FLDT_CHECK(OPERATION, MESSAGE, ...)                                                                            \
    CHECK_RET((fldt_ret_code = (OPERATION)) == VS_FLDT_ERR_OK, fldt_ret_code, MESSAGE, ##__VA_ARGS__)

bool
vs_fldt_file_is_newer(const vs_fldt_file_version_t *available, const vs_fldt_file_version_t *current);

const char *
vs_fldt_file_version_descr(char buf[FLDT_FILEVER_BUF], const vs_fldt_file_version_t *file_ver);

const char *
vs_fldt_file_type_descr(char buf[FLDT_FILEVER_BUF], const vs_fldt_file_type_t *file_type);

int
vs_fldt_send_request(const vs_netif_t *netif,
                     const vs_mac_addr_t *mac,
                     vs_sdmp_fldt_element_e element,
                     const uint8_t *data,
                     uint16_t data_sz);

// Server request/response processing

// . "Destroy"
// .  Called to destroy current file type that was initialized during vs_fldt_update_server_file_type call
typedef void (*vs_fldt_server_destroy_funct)(void **storage_context);

typedef struct {
    vs_fldt_file_type_t file_type;

    union {
        vs_firmware_descriptor_t fw_descr;
        vs_tl_header_t tl_descr;
    };

    vs_storage_op_ctx_t *storage_ctx;

} vs_fldt_server_file_type_mapping_t;

int
vs_fldt_GFTI_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);

int
vs_fldt_GNFH_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);
int
vs_fldt_GNFD_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);

int
vs_fldt_GNFF_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);

// Client request/response processing

typedef struct {
    vs_fldt_file_type_t file_type;

    union {
        vs_firmware_descriptor_t fw_descr;
        vs_tl_header_t tl_descr;
    };

    vs_storage_op_ctx_t *storage_ctx;
    vs_fldt_file_version_t previous_ver;
    vs_mac_addr_t gateway_mac;

} vs_fldt_client_file_type_mapping_t;

int
vs_fldt_INFV_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);

int
vs_fldt_GFTI_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz);

int
vs_fldt_GNFH_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz);

int
vs_fldt_GNFD_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz);

int
vs_fldt_GNFF_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz);

// Utilities

#define vs_fldt_get_mapping_elem_impl(MAPPING_ARRAY_TYPE, MAPPING_ARRAY_ELEM, MAPPING_ARRAY_SIZE, FILE_TYPE)           \
    size_t id;                                                                                                         \
    MAPPING_ARRAY_TYPE *file_mapping;                                                                                  \
                                                                                                                       \
    for (id = 0; id < MAPPING_ARRAY_SIZE; ++id) {                                                                      \
        file_mapping = &(MAPPING_ARRAY_ELEM)[id];                                                                      \
        if (!VS_IOT_MEMCMP(&file_mapping->file_type, FILE_TYPE, sizeof(*FILE_TYPE))) {                                 \
            return file_mapping;                                                                                       \
        }                                                                                                              \
    }                                                                                                                  \
                                                                                                                       \
    VS_LOG_WARNING("[FLDT] Unable to find file type specified %d", file_type->file_type_id);                           \
    return NULL;

#define FLDT_CALLBACK(FILETYPEINFO, CALLBACK, ARGUMENTS, DESCR, ...)                                                   \
    do {                                                                                                               \
        CHECK_RET((FILETYPEINFO)->CALLBACK != NULL, VS_FLDT_ERR_NO_CALLBACK, "There is no " #CALLBACK " callback");    \
        FLDT_CHECK((FILETYPEINFO)->CALLBACK ARGUMENTS, (DESCR), ##__VA_ARGS__);                                        \
    } while (0)

vs_fldt_ret_code_e
vs_firmware_version_2_vs_fldt_file_version(vs_fldt_file_version_t *dst,
                                           const vs_fldt_file_type_t *file_type,
                                           const void *src);

#ifdef __cplusplus
}
#endif

#endif // VS_SECURITY_SDK_SDMP_SERVICES_FLDT_PRIVATE_H
