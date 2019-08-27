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

#include <stdlib-config.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>
#include <virgil/iot/tests/private/test_netif.h>
#include <virgil/iot/tests/private/test_fldt.h>


/**********************************************************/
static int client_version_funct(const vs_fldt_file_type_t *file_type, vs_fldt_file_version_t *cur_file_version){
    (void) file_type;
    (void) cur_file_version;
    calls.client_get_curver = 1;
    VS_IOT_MEMCPY(cur_file_version, &to_set_client_curver, sizeof (to_set_client_curver));
    return 0;
}

/**********************************************************/
static int client_update_funct(const vs_fldt_infv_new_file_request_t *file_version_request){
    (void) file_version_request;
    calls.client_update = 1;
    return 0;
}

/**********************************************************/
static int client_info_funct(const vs_fldt_gfti_fileinfo_response_t *file_info){
    (void) file_info;
    calls.client_info = 1;
    return 0;
}

/**********************************************************/
static int client_header_funct(const vs_fldt_gnfh_header_response_t *file_header){
    (void) file_header;
    calls.client_header = 1;
    return 0;
}

/**********************************************************/
static int client_chunk_funct(const vs_fldt_gnfc_chunk_response_t *file_chunk){
    (void) file_chunk;
    calls.client_chunk = 1;
    return 0;
}

/**********************************************************/
static int client_footer_funct(const vs_fldt_gnff_footer_response_t *file_footer){
    (void) file_footer;
    calls.client_footer = 1;
    return 0;
}

/**********************************************************/
static int client_set_gateway_mac_funct(const vs_mac_addr_t *mac){
    (void) mac;
    calls.client_mac = 1;
    return 0;}

/**********************************************************/
static int server_version_funct(const vs_fldt_gfti_fileinfo_request_t *request, vs_fldt_gfti_fileinfo_response_t *response){
    (void) request;
    calls.server_curver = 1;
    VS_IOT_MEMCPY(response, &to_set_client_curver, sizeof (to_set_client_curver));
    return 0;
}

/**********************************************************/
static int server_header_funct(const vs_fldt_gnfh_header_request_t *request, uint16_t response_buf_sz, vs_fldt_gnfh_header_response_t *response){
    (void) request;
    (void) response_buf_sz;
    (void) response;
    calls.server_header = 1;
    return 0;
}

/**********************************************************/
static int server_chunk_funct(const vs_fldt_gnfc_chunk_request_t *request, uint16_t response_buf_sz, vs_fldt_gnfc_chunk_response_t *response) {
    (void) request;
    (void) response_buf_sz;
    (void) response;
    calls.server_chunk = 1;
    return server_chunk_funct_ret;
}

/**********************************************************/
static int server_footer_funct(const vs_fldt_gnff_footer_request_t *request, uint16_t response_buf_sz, vs_fldt_gnff_footer_response_t *response){
    (void) request;
    (void) response_buf_sz;
    (void) response;
    calls.server_footer = 1;
    return 0;
}

/**********************************************************/
vs_fldt_client_file_type_mapping_t
get_client_file_mapping(vs_fldt_file_type_id_t file_type) {
    vs_fldt_client_file_type_mapping_t file_mapping = {
            .file_type = {
                    .file_type_id = file_type,
                    .add_info = {0}
                    },
            .get_current_version = client_version_funct,
            .update_file = client_update_funct,
            .get_info = client_info_funct,
            .get_header = client_header_funct,
            .get_chunk = client_chunk_funct,
            .get_footer = client_footer_funct,
            .set_gateway_mac = client_set_gateway_mac_funct
    };

    return file_mapping;
}
/**********************************************************/
vs_fldt_server_file_type_mapping_t
get_server_file_mapping(vs_fldt_file_type_id_t file_type) {
    vs_fldt_server_file_type_mapping_t file_mapping = {
            .file_type = {
                    .file_type_id = file_type,
                    .add_info = {0}
            },
            .get_version = server_version_funct,
            .get_header = server_header_funct,
            .get_chunk = server_chunk_funct,
            .get_footer = server_footer_funct
    };

    return file_mapping;
}
