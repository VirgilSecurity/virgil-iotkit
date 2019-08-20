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

#ifndef VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_H
#define VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>

// File type
enum vs_fldt_file_type {
    VS_FLDT_FIRST_FILETYPE = 0,
    VS_FLDT_FIRMWARE = VS_FLDT_FIRST_FILETYPE,
    VS_FLDT_TRUSTLIST,
    VS_FLDT_OTHER,
    VS_FLDT_FILETYPES_AMOUNT
};

typedef struct __attribute__((__packed__)) {
    uint8_t file_type; // = enum vs_fldt_file_type
    uint8_t add_info[4];
} vs_fldt_file_type_t;

// File version
typedef struct __attribute__((__packed__)) {
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
    uint8_t dev_milestone;
    uint8_t dev_build;
    uint32_t timestamp; // the number of seconds elapsed since January 1, 2015 UTC
    vs_fldt_file_type_t file_type;
} vs_fldt_file_version_t;

// Commands
typedef enum {
    VS_FLDT_INFV = HTONL_IN_COMPILE_TIME('INFV'), /* Inform New File Version */
    VS_FLDT_GFTI = HTONL_IN_COMPILE_TIME('GFTI'), /* Get File Type Information */
    VS_FLDT_GNFH = HTONL_IN_COMPILE_TIME('GNFH'), /* Get New File Header */
    VS_FLDT_GNFC = HTONL_IN_COMPILE_TIME('GNFC'), /* Get New File Chunk */
    VS_FLDT_GNFF = HTONL_IN_COMPILE_TIME('GNFF'), /* Get New File Footer */
} vs_sdmp_fldt_element_e;

#define FLDT_FILE_SPEC_INFO_SZ (64)

// Get Service descriptor
const vs_sdmp_service_t *
vs_sdmp_fldt_service(const vs_netif_t *netif);

// "Inform New File Version"
typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
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
    uint16_t chunks_amount;
    uint16_t chunk_size;
    uint16_t footer_size; // zero if not present
    uint16_t header_size;
    uint8_t header_data[];
} vs_fldt_gnfh_header_response_t;

// "Get New File Chunk"
typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
    uint16_t chunk_id;
} vs_fldt_gnfc_chunk_request_t;

typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
    uint16_t chunk_id;
    uint16_t chunk_size;
    uint8_t chunk_data[];
} vs_fldt_gnfc_chunk_response_t;

// "Get New File Footer"
typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
} vs_fldt_gnff_footer_request_t;

typedef struct __attribute__((__packed__)) {
    vs_fldt_file_version_t version;
    uint16_t footer_size;
    uint8_t footer_data[];
} vs_fldt_gnff_footer_response_t;

// Functions
bool
vs_fldt_file_is_newer(const vs_fldt_file_version_t *available, const vs_fldt_file_version_t *current);

#ifdef __cplusplus
}
#endif

#endif // VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_H
