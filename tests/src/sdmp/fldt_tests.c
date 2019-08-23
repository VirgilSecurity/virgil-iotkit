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
vs_fldt_file_version_t new_firmware_file = {
        .major = 1,
        .minor = 2,
        .patch = 3,
        .dev_milestone = 4,
        .dev_build = 5,
        .timestamp = 6
};
vs_fldt_file_version_t new_trustlist_file = {
        .major = 1,
        .minor = 2,
        .patch = 3,
        .dev_milestone = 4,
        .dev_build = 5,
        .timestamp = 6
};
vs_fldt_file_version_t new_other_file = {
        .major = 1,
        .minor = 2,
        .patch = 3,
        .dev_milestone = 4,
        .dev_build = 5,
        .timestamp = 6
};
vs_fldt_file_version_t to_set_client_curver;
vs_fldt_gfti_fileinfo_response_t to_set_server_curver;
vs_fldt_gnfh_header_response_t to_set_header;
vs_fldt_gnfc_chunk_response_t to_set_chunk;
vs_fldt_gnff_footer_response_t to_set_footer;

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

    vs_logger_set_loglev(VS_LOGLEV_ALERT);

    client_file_type = get_client_file_mapping(VS_FLDT_TRUSTLIST);
    FLDT_CHECK_ERROR_GOTO(vs_fldt_add_client_file_type(NULL), "Null client file type has been added");

    vs_logger_set_loglev(prev_loglev);


    server_file_type = get_server_file_mapping(VS_FLDT_FIRMWARE);
    FLDT_CHECK_GOTO(vs_fldt_add_server_file_type(&server_file_type), "Unable to add Firmware server file mapping");

    server_file_type = get_server_file_mapping(VS_FLDT_TRUSTLIST);
    FLDT_CHECK_GOTO(vs_fldt_add_server_file_type(&server_file_type), "Unable to add Trustlist server file mapping");

    vs_logger_set_loglev(VS_LOGLEV_ALERT);

    server_file_type = get_server_file_mapping(VS_FLDT_TRUSTLIST);
    FLDT_CHECK_ERROR_GOTO(vs_fldt_add_server_file_type(NULL), "Null server file type has been added");

    vs_logger_set_loglev(prev_loglev);

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

    calls.calls = 0;

    vs_fldt_infv_new_file_request_t new_file_request;
    new_file_request.version = new_firmware_file;

    to_set_client_curver = new_firmware_file;
    to_set_client_curver.major = 0;
    to_set_client_curver.dev_build = 0;

    FLDT_CHECK_GOTO(vs_fldt_broadcast_new_file(&new_file_request), "Unable to send request");

    BOOL_CHECK_RET(calls.client_get_curver && calls.client_update && calls.client_update, "Not all callbacks have been called");

    return true;

    terminate:

    return false;
}

/**********************************************************/
// GFTI : Get File Type Information
static bool
test_GFTI(void){

    calls.calls = 0;

    vs_fldt_gfti_fileinfo_request_t fileinfo_request;
    fileinfo_request.file_type = new_trustlist_file.file_type;
    vs_fldt_set_is_gateway(true);

    FLDT_CHECK_GOTO(vs_fldt_ask_file_type_info(&fileinfo_request), "Unable to send request");

    BOOL_CHECK_RET(calls.server_curver, "Not all callbacks have been called");

    return true;

    terminate:

    return false;
}

/**********************************************************/
// GNFH : Get New File Header
static bool
test_GNFH(void){

    calls.calls = 0;

    vs_fldt_gnfh_header_request_t request;
    request.version.file_type = new_firmware_file.file_type;

    to_set_server_curver.version = new_firmware_file;

    VS_IOT_MEMCPY(&request.version, &new_trustlist_file, sizeof(new_trustlist_file));

    FLDT_CHECK_GOTO(vs_fldt_ask_file_header(&mac_addr_server, &request), "Unable to send request");

    BOOL_CHECK_RET(calls.server_header && calls.client_header, "Not all callbacks have been called");

    return true;

    terminate:

    return false;
}

/**********************************************************/
// GNFC : Get New File Chunk
static bool
test_GNFC(void){

    calls.calls = 0;

    vs_fldt_gnfc_chunk_request_t request;
    request.version.file_type = new_firmware_file.file_type;

    to_set_server_curver.version = new_firmware_file;

    VS_IOT_MEMCPY(&request.version, &new_trustlist_file, sizeof(new_trustlist_file));

    FLDT_CHECK_GOTO(vs_fldt_ask_file_chunk(&mac_addr_server, &request), "Unable to send request");

    BOOL_CHECK_RET(calls.server_chunk && calls.client_chunk, "Not all callbacks have been called");

    return true;

    terminate:

    return false;
}

/**********************************************************/
// GNFF : Get New File Footer
static bool
test_GNFF(void){

    calls.calls = 0;

    vs_fldt_gnff_footer_request_t request;
    request.version.file_type = new_firmware_file.file_type;

    to_set_server_curver.version = new_firmware_file;

    VS_IOT_MEMCPY(&request.version, &new_trustlist_file, sizeof(new_trustlist_file));

    FLDT_CHECK_GOTO(vs_fldt_ask_file_footer(&mac_addr_server, &request), "Unable to send request");

    BOOL_CHECK_RET(calls.server_footer && calls.client_footer, "Not all callbacks have been called");

    return true;

    terminate:

    return false;
}

/**********************************************************/
uint16_t
fldt_tests(void) {
    uint16_t failed_test_result = 0;

    START_TEST("FLDT");

    prepare_test_netif(&test_netif);

    mac_addr_server_call = mac_addr_server;
    mac_addr_client_call = mac_addr_client;
    new_firmware_file.file_type = make_file_type(VS_FLDT_FIRMWARE);
    new_trustlist_file.file_type = make_file_type(VS_FLDT_TRUSTLIST);
    new_other_file.file_type = make_file_type(VS_FLDT_OTHER);

    SDMP_CHECK_GOTO(vs_sdmp_init(&test_netif), "vs_sdmp_init call");

    TEST_CASE_OK("register FLDT service", test_fldt_register());
    TEST_CASE_OK("Add file types", test_fldt_add_filetypes());
    TEST_CASE_OK("Test broadcast \"Inform New File Version\" (INFV) call", test_INFV());
    TEST_CASE_OK("Test \"Get File Type Information\" (GFTI) call", test_GFTI());
    TEST_CASE_OK("Test \"Get New File Header\" (GNFH) call", test_GNFH());
    TEST_CASE_OK("Test \"Get New File Chunk\" (GNFC) call", test_GNFC());
    TEST_CASE_OK("Test \"Get New File Footer\" (GNFF) call", test_GNFF());

    SDMP_CHECK_GOTO(vs_sdmp_deinit(&test_netif), "vs_sdmp_deinit call");

terminate:

    return failed_test_result;
}
