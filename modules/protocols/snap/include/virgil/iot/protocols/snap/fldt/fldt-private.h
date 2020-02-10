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

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_FLDT_PRIVATE_H
#define VS_SECURITY_SDK_SNAP_SERVICES_FLDT_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/macros/macros.h>


//
//  Internal structures
//

#define FLDT_MAC_PRINT_TEMPLATE "%x:%x:%x:%x:%x:%x"
#define FLDT_MAC_PRINT_ARG(MAC_ADDR)                                                                                   \
    (MAC_ADDR).bytes[0], (MAC_ADDR).bytes[1], (MAC_ADDR).bytes[2], (MAC_ADDR).bytes[3], (MAC_ADDR).bytes[4],           \
            (MAC_ADDR).bytes[5]

#define VS_SNAP_PRINT_DEBUG(SNAP_CMD, STR, ...)                                                                        \
    do {                                                                                                               \
        if (vs_logger_is_loglev(VS_LOGLEV_DEBUG)) {                                                                    \
            union {                                                                                                    \
                uint8_t byte[sizeof(uint32_t) + 1];                                                                    \
                uint32_t dword;                                                                                        \
            } buf;                                                                                                     \
            VS_IOT_MEMSET(buf.byte, 0, sizeof(buf.byte));                                                              \
            buf.dword = ntohl((uint32_t)SNAP_CMD);                                                                     \
            VS_LOG_DEBUG("[%s] " STR, (char *)buf.byte, ##__VA_ARGS__);                                                \
        }                                                                                                              \
    } while (0)

#define DEBUG_FW_TYPE_STR "[Type FW]"
#define DEBUG_TL_TYPE_STR "[Type TL]"
#define DEBUG_USER_TYPE_STR "[Type USER]"

#define VS_FLDT_PRINT_DEBUG(FILE_TYPE, SNAP_CMD, STR, ...)                                                             \
    do {                                                                                                               \
        if (vs_logger_is_loglev(VS_LOGLEV_DEBUG)) {                                                                    \
            switch (FILE_TYPE) {                                                                                       \
            case VS_UPDATE_FIRMWARE:                                                                                   \
                VS_SNAP_PRINT_DEBUG(SNAP_CMD, "%s %s", DEBUG_FW_TYPE_STR, STR);                                        \
                break;                                                                                                 \
            case VS_UPDATE_TRUST_LIST:                                                                                 \
                VS_SNAP_PRINT_DEBUG(SNAP_CMD, "%s %s", DEBUG_TL_TYPE_STR, STR);                                        \
                break;                                                                                                 \
            default:                                                                                                   \
                VS_SNAP_PRINT_DEBUG(SNAP_CMD, "%s %s", DEBUG_USER_TYPE_STR, STR);                                      \
                break;                                                                                                 \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

// Commands
// mute "error: multi-character character constant" message
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"

typedef enum { VS_FLDT_SERVICE_ID = HTONL_IN_COMPILE_TIME('FLDT') } vs_fldt_t;

typedef enum {
    VS_FLDT_INFV = HTONL_IN_COMPILE_TIME('INFV'), /* Inform New File Version */
    VS_FLDT_GNFH = HTONL_IN_COMPILE_TIME('GNFH'), /* Get New File Header */
    VS_FLDT_GNFD = HTONL_IN_COMPILE_TIME('GNFD'), /* Get New File Data */
    VS_FLDT_GNFF = HTONL_IN_COMPILE_TIME('GNFF'), /* Get New File Footer */
} vs_snap_fldt_element_e;
#pragma GCC diagnostic pop

// Get Service descriptor

// File Information
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    vs_mac_addr_t gateway_mac;
} vs_fldt_file_info_t;

// "Inform New File Version"
typedef vs_fldt_file_info_t vs_fldt_infv_new_file_request_t;

// "Get New File Header"
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
} vs_fldt_gnfh_header_request_t;

typedef struct __attribute__((__packed__)) {
    vs_fldt_file_info_t fldt_info;
    uint32_t file_size;
    uint8_t has_footer;
    uint16_t header_size;
    uint8_t header_data[];
} vs_fldt_gnfh_header_response_t;

// "Get New File Data"
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    uint32_t offset;
} vs_fldt_gnfd_data_request_t;

typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    uint32_t offset;
    uint32_t next_offset;
    uint16_t data_size;
    uint8_t data[];
} vs_fldt_gnfd_data_response_t;

// "Get New File Footer"
typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
} vs_fldt_gnff_footer_request_t;

typedef struct __attribute__((__packed__)) {
    vs_update_file_type_t type;
    uint16_t footer_size;
    uint8_t footer_data[];
} vs_fldt_gnff_footer_response_t;

typedef struct {
    vs_update_file_type_t type;
    vs_file_version_t prev_file_version; // for client only
    vs_file_version_t cur_file_version;
    vs_update_interface_t update_context;
    vs_mac_addr_t gateway_mac; // for client only
} vs_fldt_file_type_mapping_t;

// Client request/response processing
#ifdef __cplusplus
}
#endif

#endif // VS_SECURITY_SDK_SNAP_SERVICES_FLDT_PRIVATE_H
