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

#include <stdbool.h>
#include <virgil/iot/tests/private/test_netif.h>
#include <virgil/iot/tests/private/test_fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>

static vs_netif_t test_netif;
static const vs_mac_addr_t mac_addr_server = {.bytes = {0xF2, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6}};
static const vs_mac_addr_t mac_addr_client = {.bytes = {0x12, 0x12, 0x13, 0x14, 0x15, 0x16}};
vs_fldt_file_version_t filetype1 = {
        .major = 1,
        .minor = 2,
        .patch = 3,
        .dev_milestone = 4,
        .dev_build = 5,
        .timestamp = 6
};
vs_fldt_file_version_t filetype2 = {
        .major = 1,
        .minor = 2,
        .patch = 3,
        .dev_milestone = 4,
        .dev_build = 5,
        .timestamp = 6
};
vs_fldt_file_version_t filetype3 = {
        .major = 1,
        .minor = 2,
        .patch = 3,
        .dev_milestone = 4,
        .dev_build = 5,
        .timestamp = 6
};
vs_fldt_file_version_t to_set_client_curver;
vs_fldt_gfti_fileinfo_response_t to_set_server_curver;
int server_chunk_funct_ret = 0;

calls_t calls;

/**********************************************************/
static bool
test_fldt_add_filetypes(void) {
    vs_log_level_t prev_loglev = vs_logger_get_loglev();
    vs_fldt_client_file_type_mapping_t client_file_type;
    vs_fldt_server_file_type_mapping_t server_file_type;

    client_file_type = get_client_file_mapping(VS_FLDT_FIRMWARE);
    FLDT_CHECK_GOTO(vs_fldt_add_client_file_type(&client_file_type), "Unable to add Firmware client file mapping");

    client_file_type = get_client_file_mapping(VS_FLDT_TRUSTLIST);
    FLDT_CHECK_GOTO(vs_fldt_add_client_file_type(&client_file_type), "Unable to add Trustlist client file mapping");

    client_file_type = get_client_file_mapping(VS_FLDT_TRUSTLIST);
    FLDT_CHECK_ERROR_GOTO(vs_fldt_add_client_file_type(NULL), "Null client file type has been added");

    server_file_type = get_server_file_mapping(VS_FLDT_FIRMWARE);
    FLDT_CHECK_GOTO(vs_fldt_add_server_file_type(&server_file_type), "Unable to add Firmware server file mapping");

    server_file_type = get_server_file_mapping(VS_FLDT_TRUSTLIST);
    FLDT_CHECK_GOTO(vs_fldt_add_server_file_type(&server_file_type), "Unable to add Trustlist server file mapping");

    server_file_type = get_server_file_mapping(VS_FLDT_TRUSTLIST);
    FLDT_CHECK_ERROR_GOTO(vs_fldt_add_server_file_type(NULL), "Null server file type has been added");

    return true;
    
    terminate:
    
    return false;
}

/**********************************************************/
static bool
test_fldt_register(void) {

    SDMP_CHECK_GOTO(vs_sdmp_register_service(vs_sdmp_fldt_service(&test_netif)), "vs_sdmp_init call");

    return true;

    terminate:

    return false;
}

/**********************************************************/
// INFV : Inform New File Version
static bool
test_INFV(void){

    vs_fldt_infv_new_file_request_t new_file_request;
    uint8_t prev_file_type;
    vs_log_level_t prev_loglev;

    new_file_request.version = filetype1;

    to_set_client_curver = filetype1;
    to_set_client_curver.major = 0;
    to_set_client_curver.dev_build = 0;

    to_set_server_curver.version = filetype1;
    to_set_server_curver.version.major = 1;
    to_set_server_curver.version.dev_build = 1;
    to_set_server_curver.version.timestamp = 145;
    to_set_server_curver.version.dev_milestone = 1;

    calls.calls = 0;
    FLDT_CHECK_GOTO(vs_fldt_broadcast_new_file(&new_file_request), "Unable to send request");
    BOOL_CHECK_RET(calls.client_get_curver && calls.client_update && calls.client_mac, "Not all callbacks have been called");

    to_set_client_curver = filetype1;

    calls.calls = 0;
    FLDT_CHECK_GOTO(vs_fldt_broadcast_new_file(&new_file_request), "Unable to send request");
    BOOL_CHECK_RET(calls.client_get_curver && !calls.client_update, "Incorrect callbacks have been called for not needed file type");

    prev_file_type = new_file_request.version.file_type.file_type_id;
    new_file_request.version.file_type.file_type_id = VS_FLDT_OTHER;

    calls.calls = 0;
    FLDT_CHECK_GOTO_HIDE_ERROR(vs_fldt_broadcast_new_file(&new_file_request), "Incorrect send request for non registered file type processing");
    BOOL_CHECK_RET(!calls.calls, "Incorrect callbacks have been called for non registered file type");

    new_file_request.version.file_type.file_type_id = prev_file_type;

    return true;

    terminate:

    return false;
}

/**********************************************************/
// GFTI : Get File Type Information
static bool
test_GFTI(vs_fldt_file_type_id_t elem){

    vs_fldt_gfti_fileinfo_request_t fileinfo_request;
    vs_log_level_t prev_loglev;

    fileinfo_request.file_type = filetype2.file_type;
    vs_fldt_set_is_gateway(true);

    calls.calls = 0;
    FLDT_CHECK_GOTO(vs_fldt_ask_file_type_info(&fileinfo_request), "Unable to send request");
    BOOL_CHECK_RET(calls.server_curver && calls.client_info, "Not all callbacks have been called");

    fileinfo_request.file_type.file_type_id = elem;
    calls.calls = 0;
    FLDT_CHECK_GOTO_HIDE_ERROR(vs_fldt_ask_file_type_info(&fileinfo_request), "Incorrect send request for non registered file type processing");
    BOOL_CHECK_RET(!calls.calls, "Incorrect calls were made");

    return true;

    terminate:

    return false;
}

/**********************************************************/
// GNFH : Get New File Header
static bool
test_GNFH(vs_fldt_file_type_id_t elem){

    vs_fldt_gnfh_header_request_t request;
    vs_log_level_t prev_loglev;
    uint8_t prev_file_type;

    request.version.file_type = filetype1.file_type;
    to_set_server_curver.version = filetype1;
    VS_IOT_MEMCPY(&request.version, &filetype2, sizeof(filetype2));

    prev_file_type = request.version.file_type.file_type_id;
    request.version.file_type.file_type_id = elem;

    calls.calls = 0;
    FLDT_CHECK_GOTO_HIDE_ERROR(vs_fldt_ask_file_header(&mac_addr_server, &request), "Incorrect unsupported file type processing");
    BOOL_CHECK_RET(!calls.calls, "Incorrect calls were made");

    request.version.file_type.file_type_id = prev_file_type;
    calls.calls = 0;
    FLDT_CHECK_GOTO(vs_fldt_ask_file_header(&mac_addr_server, &request), "Unable to send request");
    BOOL_CHECK_RET(calls.server_header && calls.client_header, "Not all callbacks have been called");

    return true;

    terminate:

    return false;
}

/**********************************************************/
// GNFC : Get New File Chunk
static bool
test_GNFC(vs_fldt_file_type_id_t elem){

    vs_fldt_gnfc_chunk_request_t request;
    vs_log_level_t prev_loglev;
    uint8_t prev_file_type;

    request.version.file_type = filetype1.file_type;
    to_set_server_curver.version = filetype1;
    VS_IOT_MEMCPY(&request.version, &filetype2, sizeof(filetype2));

    calls.calls = 0;
    FLDT_CHECK_GOTO(vs_fldt_ask_file_chunk(&mac_addr_server, &request), "Unable to send request");
    BOOL_CHECK_RET(calls.server_chunk && calls.client_chunk, "Incorrect not existed file chunk calls");

    prev_file_type = request.version.file_type.file_type_id;
    request.version.file_type.file_type_id = elem;

    calls.calls = 0;
    FLDT_CHECK_GOTO_HIDE_ERROR(vs_fldt_ask_file_chunk(&mac_addr_server, &request), "Incorrect unsupported file type processing");
    BOOL_CHECK_RET(!calls.calls, "Incorrect unsupported file type calls");

    request.version.file_type.file_type_id = prev_file_type;
    server_chunk_funct_ret = -1;

    calls.calls = 0;
    FLDT_CHECK_GOTO_HIDE_ERROR(vs_fldt_ask_file_chunk(&mac_addr_server, &request), "Incorrect not existed file chunk processing");
    BOOL_CHECK_RET(calls.server_chunk, "Incorrect not existed file chunk calls");

    server_chunk_funct_ret = 0;

    return true;

    terminate:

    return false;
}

/**********************************************************/
// GNFF : Get New File Footer
static bool
test_GNFF(vs_fldt_file_type_id_t elem){

    vs_log_level_t prev_loglev;
    uint8_t prev_file_type;

    vs_fldt_gnff_footer_request_t request;
    request.version.file_type = filetype1.file_type;

    to_set_server_curver.version = filetype1;

    VS_IOT_MEMCPY(&request.version, &filetype2, sizeof(filetype2));

    calls.calls = 0;
    FLDT_CHECK_GOTO(vs_fldt_ask_file_footer(&mac_addr_server, &request), "Unable to send request");
    BOOL_CHECK_RET(calls.server_footer && calls.client_footer, "Not all callbacks have been called");

    prev_file_type = request.version.file_type.file_type_id;
    request.version.file_type.file_type_id = elem;

    calls.calls = 0;
    FLDT_CHECK_GOTO_HIDE_ERROR(vs_fldt_ask_file_footer(&mac_addr_server, &request), "Unable to send request");
    BOOL_CHECK_RET(!calls.calls, "Incorrect unsupported file type calls");

    request.version.file_type.file_type_id = prev_file_type;

    return true;

    terminate:

    return false;
}

/**********************************************************/
uint16_t
fldt_tests(vs_fldt_file_type_id_t elem1, vs_fldt_file_type_id_t elem2, vs_fldt_file_type_id_t elem3) {
    uint16_t failed_test_result = 0;

    START_TEST("FLDT");

    prepare_test_netif(&test_netif);

    mac_addr_server_call = mac_addr_server;
    mac_addr_client_call = mac_addr_client;
    filetype1.file_type.file_type_id = elem1;
    filetype2.file_type.file_type_id = elem2;
    filetype3.file_type.file_type_id = elem3;

    SDMP_CHECK_GOTO(vs_sdmp_init(&test_netif), "vs_sdmp_init call");

    TEST_CASE_OK("register FLDT service", test_fldt_register());
    TEST_CASE_OK("Add file types", test_fldt_add_filetypes());
    TEST_CASE_OK("Test broadcast \"Inform New File Version\" (INFV) call", test_INFV());
    TEST_CASE_OK("Test \"Get File Type Information\" (GFTI) call", test_GFTI(elem3));
    TEST_CASE_OK("Test \"Get New File Header\" (GNFH) call", test_GNFH(elem3));
    TEST_CASE_OK("Test \"Get New File Chunk\" (GNFC) call", test_GNFC(elem3));
    TEST_CASE_OK("Test \"Get New File Footer\" (GNFF) call", test_GNFF(elem3));

    SDMP_CHECK_GOTO(vs_sdmp_deinit(&test_netif), "vs_sdmp_deinit call");

terminate:

    return failed_test_result;
}
