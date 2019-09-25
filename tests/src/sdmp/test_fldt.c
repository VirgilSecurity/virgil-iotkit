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

#if 0
#include <stdlib-config.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>
#include <virgil/iot/tests/private/test_netif.h>
#include <virgil/iot/tests/private/test_fldt.h>

vs_fldt_file_type_mapping_t server_add_filetype_to_copy;
vs_update_file_version_t client_get_current_file_version;
vs_fldt_gfti_fileinfo_response_t server_get_version_file;
vs_update_file_version_t file_ver;

/**********************************************************/
static vs_status_code_e client_set_gateway_mac(const vs_mac_addr_t *mac){
    (void) mac;

    calls.client_set_gateway_mac = 1;

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_code_e client_get_current_version(void **storage_context, const vs_update_file_type_t *file_type, vs_update_file_version_t *file_version){
    (void) storage_context;
    (void) file_type;
    (void) file_version;

    calls.client_get_current_version = 1;
    VS_IOT_MEMCPY(file_version, &client_get_current_file_version, sizeof(client_get_current_file_version));

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_code_e client_update_file(void **storage_context, const vs_fldt_infv_new_file_request_t *file_version_request){
    (void) storage_context;
    (void) file_version_request;

    calls.client_update_file = 1;

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_code_e client_got_info(void **storage_context, const vs_fldt_gfti_fileinfo_response_t *file_info){
    (void) storage_context;
    (void) file_info;

    calls.client_got_info = 1;

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_code_e client_got_header(void **storage_context, const vs_fldt_gnfh_header_response_t *file_header){
    (void) storage_context;
    (void) file_header;

    calls.client_got_header = 1;

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_code_e client_got_data(void **storage_context, const vs_fldt_gnfd_data_response_t *file_data){
    (void) storage_context;
    (void) file_data;

    calls.client_got_chunk = 1;

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_code_e client_got_footer(void **storage_context, const vs_fldt_gnff_footer_response_t *file_footer){
    (void) storage_context;
    (void) file_footer;

    calls.client_got_footer = 1;

    return VS_CODE_OK;
}

/**********************************************************/
static void client_destroy(void **storage_context){
    (void) storage_context;

    ++calls.client_destroy;
}

/**********************************************************/
static vs_status_code_e server_get_version(void **storage_context, const vs_fldt_gfti_fileinfo_request_t *request, vs_fldt_gfti_fileinfo_response_t *response){
    (void) storage_context;
    (void) request;
    (void) response;

    calls.server_version = 1;

    VS_IOT_MEMCPY(response, &server_get_version_file, sizeof(server_get_version_file));

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_code_e server_get_header(void **storage_context, const vs_fldt_gnfh_header_request_t *request, uint16_t response_buf_sz, vs_fldt_gnfh_header_response_t *response){
    (void) storage_context;
    (void) request;
    (void) response_buf_sz;
    (void) response;

    calls.server_header = 1;

    response->version = file_ver;

    return VS_CODE_OK;
}


/**********************************************************/
static vs_status_code_e server_get_chunk(void **storage_context, const vs_fldt_gnfd_data_request_t *request, uint16_t response_buf_sz, vs_fldt_gnfd_data_response_t *response){
    (void) storage_context;
    (void) request;
    (void) response_buf_sz;
    (void) response;

    calls.server_chunk = 1;

    response->version = file_ver;

    return VS_CODE_OK;
}

/**********************************************************/
static vs_status_code_e server_get_footer(void **storage_context, const vs_fldt_gnff_footer_request_t *request, uint16_t response_buf_sz, vs_fldt_gnff_footer_response_t *response){
    (void) storage_context;
    (void) request;
    (void) response_buf_sz;
    (void) response;

    calls.server_footer = 1;

    response->version = file_ver;

    return VS_CODE_OK;
}

/**********************************************************/
static void server_destroy(void **storage_get_context){
    (void) storage_get_context;

    ++calls.server_destroy;
}


/**********************************************************/
vs_status_code_e server_add_filetype(const vs_update_file_type_t *file_type){
    (void) file_type;

    calls.server_add_filetype = 1;

    return vs_fldt_update_server_file_type(&server_add_filetype_to_copy);
}

/**********************************************************/
vs_fldt_file_type_mapping_t
make_client_mapping(const vs_update_file_type_t *file_type){
    vs_fldt_file_type_mapping_t mapping = {
            .storage_context = NULL,
            .set_gateway_mac = client_set_gateway_mac,
            .get_current_version = client_get_current_version,
            .update_file = client_update_file,
            .got_info = client_got_info,
            .got_header = client_got_header,
            .got_chunk = client_got_chunk,
            .got_footer = client_got_footer,
            .destroy = client_destroy
    };

    VS_IOT_MEMCPY(&mapping.file_type, file_type, sizeof(*file_type));

    return mapping;
}

/**********************************************************/
vs_fldt_file_type_mapping_t
make_server_mapping(const vs_update_file_type_t *file_type){
    vs_fldt_file_type_mapping_t mapping = {
            .storage_context = NULL,
            .get_version = server_get_version,
            .get_header = server_get_header,
            .get_chunk = server_get_chunk,
            .get_footer = server_get_footer,
            .destroy = server_destroy,
    };

    VS_IOT_MEMCPY(&mapping.file_type, file_type, sizeof(*file_type));

    return mapping;
}

#endif