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

#ifndef VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H
#define VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_private.h>


//
//  Callbacks
//

// . "Get Current Version"
// .  Get file_type current file version and store it to the file_info
typedef int (*vs_fldt_client_get_version_funct)(const vs_fldt_file_type_t *file_type,
                                                vs_fldt_file_version_t *file_info);

// . "Update file"
// .  Current file specified by file_version is older than gateway one, so need to call
//    get_file_header, get_file_chunk, ..., get_file_footer (if footer is present)
typedef int (*vs_fldt_client_update_file_funct)(const vs_fldt_file_version_t *file_version);

// . "Get file info"
// .  File header for file file_version has been received
// .  This is response for the vs_fldt_ask_file_type_info call
typedef int (*vs_fldt_client_get_info_funct)(const vs_fldt_gfti_fileinfo_response_t *file_info);

// . "Get file header"
// .  File header for file file_version has been received
// .  This is response for the vs_fldt_ask_file_header call
typedef int (*vs_fldt_client_get_header_funct)(const vs_fldt_gnfh_header_response_t *file_header);

// . "Get file chunk"
// .  File data chunk for file file_version has been received
// .  This is response for the vs_fldt_ask_file_chunk call
typedef int (*vs_fldt_client_get_chunk_funct)(const vs_fldt_gnfc_chunk_response_t *file_chunk);

// . "Get file footer"
// .  File footer for file file_version has been received
// .  This is response for the vs_fldt_ask_file_footer call
typedef int (*vs_fldt_client_get_footer_funct)(const vs_fldt_gnff_footer_response_t *file_footer);


//
//  Internal structures
//

typedef struct {
    vs_fldt_storage_ctx_t storage_context;
    vs_fldt_file_type_t file_type;
    vs_fldt_storage_id_t id;

    vs_fldt_client_get_version_funct get_current_version;
    vs_fldt_client_update_file_funct update_file;
    vs_fldt_client_get_info_funct get_info;
    vs_fldt_client_get_header_funct get_header;
    vs_fldt_client_get_chunk_funct get_chunk;
    vs_fldt_client_get_footer_funct get_footer;
} vs_fldt_client_file_type_mapping_t;


//
//  Customer API
//

int
vs_fldt_add_client_file_type(const vs_fldt_client_file_type_mapping_t *mapping_elem);

int
vs_fldt_ask_file_type_info(const vs_mac_addr_t *mac, const vs_fldt_gfti_fileinfo_request_t *file_type);

int
vs_fldt_ask_file_header(const vs_mac_addr_t *mac, const vs_fldt_gnfh_header_request_t *header_request);

int
vs_fldt_ask_file_chunk(const vs_mac_addr_t *mac, vs_fldt_gnfc_chunk_request_t *file_chunk);

int
vs_fldt_ask_file_footer(const vs_mac_addr_t *mac, const vs_fldt_gnff_footer_request_t *file_footer);

#ifdef __cplusplus
}
#endif

#endif // VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H
