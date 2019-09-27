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

#ifndef VS_IOT_SDK_TESTS_FLDT_H_
#define VS_IOT_SDK_TESTS_FLDT_H_

#if 0
#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>

typedef struct {
    union {
        uint32_t calls;
        struct {
            uint32_t server_version : 1, server_header : 1, server_chunk : 1, server_footer : 1, server_destroy : 3,
            server_add_filetype : 1, client_set_gateway_mac : 1, client_get_current_version : 1, client_update_file : 1,
            client_got_info : 1, client_got_header : 1, client_got_chunk : 1, client_got_footer : 1, client_destroy : 3;
        };
    };
} calls_t;
calls_t calls;
vs_fldt_file_type_mapping_t server_add_filetype_to_copy;
vs_update_file_version_t client_get_current_file_version;
vs_fldt_gfti_fileinfo_response_t server_get_version_file;
vs_update_file_version_t file_ver;

vs_fldt_file_type_mapping_t
make_client_mapping(const vs_update_file_type_t *file_type);

vs_fldt_file_type_mapping_t
make_server_mapping(const vs_update_file_type_t *file_type);

vs_status_code_e
server_add_filetype(const vs_update_file_type_t *file_type);

#endif

#endif // VS_IOT_SDK_TESTS_FLDT_H_
