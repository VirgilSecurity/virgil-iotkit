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

#ifndef VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_SERVER_H
#define VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif


#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_private.h>

struct vs_fldt_server_file_type_mapping_t;

//
//  Callbacks
//

// . "Get File Version"
// .  Get file version for request and store it to the response
typedef vs_fldt_ret_code_e (*vs_fldt_server_version_funct)(void **storage_context,
                                                           const vs_fldt_gfti_fileinfo_request_t *request,
                                                           vs_fldt_gfti_fileinfo_response_t *response);

// . "Get File Header"
// .  Get file header for request and try to store it to the header_response buffer if response_buf_size is enough
// .  Check that response's size is enough (check response_buf_sz value)
typedef vs_fldt_ret_code_e (*vs_fldt_server_header_funct)(void **storage_context,
                                                          const vs_fldt_gnfh_header_request_t *request,
                                                          uint16_t response_buf_sz,
                                                          vs_fldt_gnfh_header_response_t *response);

// . "Get File Chunk"
// .  Get file chunk for request and try to store it to the header_response buffer if response_buf_size is enough
// .  Check that response's size is enough (check response_buf_sz value)
typedef vs_fldt_ret_code_e (*vs_fldt_server_chunk_funct)(void **storage_context,
                                                         const vs_fldt_gnfc_chunk_request_t *request,
                                                         uint16_t response_buf_sz,
                                                         vs_fldt_gnfc_chunk_response_t *response);

// . "Get File Footer"
// .  Get file footer for request and try to store it to the header_response buffer if response_buf_size is enough
// .  Check that response's size is enough (check response_buf_sz value)
typedef vs_fldt_ret_code_e (*vs_fldt_server_footer_funct)(void **storage_context,
                                                          const vs_fldt_gnff_footer_request_t *request,
                                                          uint16_t response_buf_sz,
                                                          vs_fldt_gnff_footer_response_t *response);

// . "Destroy"
// .  Called to desctroy current file type that was initialized during vs_fldt_update_server_file_type call
typedef void (*vs_fldt_server_destroy_funct)(void **storage_context);


//
//  Internal structures
//

typedef struct {
    vs_fldt_file_type_t file_type;
    void *storage_context;

    vs_fldt_server_version_funct get_version;
    vs_fldt_server_header_funct get_header;
    vs_fldt_server_chunk_funct get_chunk;
    vs_fldt_server_footer_funct get_footer;
    vs_fldt_server_destroy_funct destroy;
} vs_fldt_server_file_type_mapping_t;


//
//  Customer API
//

vs_fldt_ret_code_e
vd_fldt_init_server(void);

vs_fldt_ret_code_e
vs_fldt_update_server_file_type(const vs_fldt_server_file_type_mapping_t *mapping_elem);

vs_fldt_ret_code_e
vs_fldt_broadcast_new_file(const vs_fldt_infv_new_file_request_t *new_file);

void
vd_fldt_destroy_server(void);

#ifdef __cplusplus
}
#endif

#endif // VIRGIL_SECURITY_SDK_SDMP_SERVICES_FLDT_SERVER_H
