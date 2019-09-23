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

#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/status_code/status_code.h>

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

const vs_netif_t *vs_fldt_netif;
const vs_mac_addr_t *vs_fldt_broadcast_mac_addr;
bool vs_fldt_is_gateway;

vs_status_code_e
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

vs_status_code_e
vs_fldt_GFTI_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);

vs_status_code_e
vs_fldt_GNFH_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);
vs_status_code_e
vs_fldt_GNFD_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);

vs_status_code_e
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

vs_status_code_e
vs_fldt_INFV_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);

vs_status_code_e
vs_fldt_GFTI_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz);

vs_status_code_e
vs_fldt_GNFH_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz);

vs_status_code_e
vs_fldt_GNFD_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz);

vs_status_code_e
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
        CHECK_RET((FILETYPEINFO)->CALLBACK != NULL, VS_CODE_ERR_NO_CALLBACK, "There is no " #CALLBACK " callback");    \
        FLDT_CHECK((FILETYPEINFO)->CALLBACK ARGUMENTS, (DESCR), ##__VA_ARGS__);                                        \
    } while (0)

static inline void
vs_fldt_set_is_gateway(bool is_gateway) {
    vs_fldt_is_gateway = is_gateway;
}

vs_status_code_e
vs_firmware_version_2_vs_fldt_file_version(vs_fldt_file_version_t *dst,
                                           const vs_fldt_file_type_t *file_type,
                                           const void *src);

#ifdef __cplusplus
}
#endif

#endif // VS_SECURITY_SDK_SDMP_SERVICES_FLDT_PRIVATE_H
