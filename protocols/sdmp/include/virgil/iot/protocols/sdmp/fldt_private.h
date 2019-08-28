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

#ifndef VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_PRIVATE_H
#define VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/logger/logger.h>

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

typedef uint16_t vs_fldt_storage_id_t;
const vs_netif_t *vs_fldt_netif;
const vs_mac_addr_t *vs_fldt_broadcast_mac_addr;

int
vs_fldt_send_request(const vs_netif_t *netif,
                     const vs_mac_addr_t *mac,
                     vs_sdmp_fldt_element_e element,
                     const uint8_t *data,
                     uint16_t data_sz);

// Server request/response processing

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
vs_fldt_GNFC_request_processing(const uint8_t *request,
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
vs_fldt_GNFC_response_processor(bool is_ack, const uint8_t *response, const uint16_t response_sz);

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
    VS_LOG_WARNING("[FLDT] Unable to find file type specified %ul", file_type->file_type_id);                          \
    return NULL;

#ifdef __cplusplus
}
#endif

#endif // VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_PRIVATE_H
