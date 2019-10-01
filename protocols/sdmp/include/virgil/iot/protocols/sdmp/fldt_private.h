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

#define FLDT_FILEVER_BUF (196)      // buffer for vs_fldt_file_version_descr
#define FLDT_FILE_SPEC_INFO_SZ (64) // vs_fldt_infv_new_file_request_t.file_specific_info field size

#define FLDT_GATEWAY_TEMPLATE "%x:%x:%x:%x:%x:%x"
#define FLDT_GATEWAY_ARG(MAC_ADDR)                                                                                     \
    (MAC_ADDR).bytes[0], (MAC_ADDR).bytes[1], (MAC_ADDR).bytes[2], (MAC_ADDR).bytes[3], (MAC_ADDR).bytes[4],           \
            (MAC_ADDR).bytes[5]

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

// File Information
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    vs_update_file_version_t version;
    vs_mac_addr_t gateway_mac;
} vs_fldt_file_info_t;

// "Inform New File Version"
typedef vs_fldt_file_info_t vs_fldt_infv_new_file_request_t;

typedef void vs_fldt_infv_new_file_response_t;

// "Get File Type Information"
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
} vs_fldt_gfti_fileinfo_request_t;

typedef vs_fldt_file_info_t vs_fldt_gfti_fileinfo_response_t;

// "Get New File Header"
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    vs_update_file_version_t version;
} vs_fldt_gnfh_header_request_t;

typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    vs_update_file_version_t version;
    uint32_t file_size;
    uint8_t has_footer;
    uint16_t header_size;
    uint8_t header_data[];
} vs_fldt_gnfh_header_response_t;

// "Get New File Data"
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    vs_update_file_version_t version;
    uint32_t offset;
} vs_fldt_gnfd_data_request_t;

typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    vs_update_file_version_t version;
    uint32_t offset;
    uint32_t next_offset;
    uint16_t data_size;
    uint8_t data[];
} vs_fldt_gnfd_data_response_t;

// "Get New File Footer"
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    vs_update_file_version_t version;
} vs_fldt_gnff_footer_request_t;

typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    vs_update_file_version_t version;
    uint16_t footer_size;
    uint8_t footer_data[];
} vs_fldt_gnff_footer_response_t;

typedef struct {
    vs_update_file_type_t type;
    vs_update_file_version_t prev_file_version; // for client only
    vs_update_file_version_t cur_file_version;
    vs_update_interface_t update_context;
    vs_mac_addr_t gateway_mac; // for client only
} vs_fldt_file_type_mapping_t;

// Utilities
#define FLDT_CHECK(OPERATION, MESSAGE, ...)                                                                            \
    CHECK_RET((fldt_ret_code = (OPERATION)) == VS_CODE_OK, fldt_ret_code, MESSAGE, ##__VA_ARGS__)

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

int
vs_fldt_INFV_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz);

int
vs_fldt_GNFH_response_processor(bool is_ack, const uint8_t *response, uint16_t response_sz);

int
vs_fldt_GNFD_response_processor(bool is_ack, const uint8_t *response, uint16_t response_sz);

int
vs_fldt_GNFF_response_processor(bool is_ack, const uint8_t *response, uint16_t response_sz);

#ifdef __cplusplus
}
#endif

#endif // VS_SECURITY_SDK_SDMP_SERVICES_FLDT_PRIVATE_H
