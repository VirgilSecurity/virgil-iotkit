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

#ifndef VIRGIL_IOT_SDK_TESTS_FLDT_H_
#define VIRGIL_IOT_SDK_TESTS_FLDT_H_

#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>

typedef struct {
    union {
        uint16_t calls;
        struct {
            uint16_t server_curver : 1, server_header : 1, server_chunk : 1, server_footer : 1,
            client_get_curver : 1, client_update : 1, client_info : 1, client_header : 1, client_chunk : 1, client_footer : 1, client_mac : 1;
        };
    };
} calls_t;
calls_t calls;

vs_fldt_file_version_t filetype1;
vs_fldt_file_version_t filetype2;
vs_fldt_file_version_t filetype3;
vs_fldt_file_version_t to_set_client_curver;
vs_fldt_gfti_fileinfo_response_t to_set_server_curver;
int server_chunk_funct_ret;

vs_fldt_server_file_type_mapping_t
get_server_file_mapping(vs_fldt_file_type_id_t file_type);

vs_fldt_client_file_type_mapping_t
get_client_file_mapping(vs_fldt_file_type_id_t file_type);


#define FLDT_CHECK_GOTO(OPERATION, DESCRIPTION, ...)                                                                   \
    if ((OPERATION)) {                                                                                            \
        VS_LOG_ERROR((DESCRIPTION), ##__VA_ARGS__);                                                                    \
        goto terminate;                                                                                                \
    }

#define FLDT_CHECK_ERROR_GOTO(OPERATION, DESCRIPTION, ...)  do {                                                                 \
        prev_loglev = vs_logger_get_loglev();   \
        vs_logger_set_loglev(VS_LOGLEV_ALERT);  \
    if (!(OPERATION)) {                                                                                            \
        vs_logger_set_loglev(prev_loglev);  \
        VS_LOG_ERROR((DESCRIPTION), ##__VA_ARGS__);                                                                    \
        goto terminate;                                                                                                \
    } else {  \
        vs_logger_set_loglev(prev_loglev);  \
    }   \
    } while(0)

#define FLDT_CHECK_GOTO_HIDE_ERROR(OPERATION, DESCRIPTION, ...)  do {                                                                 \
        prev_loglev = vs_logger_get_loglev();   \
        vs_logger_set_loglev(VS_LOGLEV_ALERT);  \
    if ((OPERATION)) {                                                                                            \
        vs_logger_set_loglev(prev_loglev);  \
        VS_LOG_ERROR((DESCRIPTION), ##__VA_ARGS__);                                                                    \
        goto terminate;                                                                                                \
    } else {  \
        vs_logger_set_loglev(prev_loglev);  \
    }   \
    } while(0)

#endif // VIRGIL_IOT_SDK_TESTS_FLDT_H_
