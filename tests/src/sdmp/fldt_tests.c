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

#include <stdint.h>
#include <virgil/iot/tests/helpers.h>

#include <stdbool.h>
#include <virgil/iot/tests/private/netif_test_impl.h>
#include <virgil/iot/tests/private/test_fldt.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/trust_list/trust_list.h>

#define FLDT_CHECK_GOTO(OPERATION, CALLS, DESCRIPTION, ...)                                                            \
    CHECK(VS_CODE_OK == (OPERATION) && (CALLS), DESCRIPTION, ##__VA_ARGS__)

#define FLDT_CHECK_ERROR_GOTO(OPERATION, CALLS, DESCRIPTION, ...)                                                      \
    do {                                                                                                               \
        prev_loglev = vs_logger_get_loglev();                                                                          \
        vs_logger_set_loglev(VS_LOGLEV_ALERT);                                                                         \
        if (VS_CODE_OK != (OPERATION) || !(CALLS)) {                                                                   \
            vs_logger_set_loglev(prev_loglev);                                                                         \
            VS_LOG_ERROR((DESCRIPTION), ##__VA_ARGS__);                                                                \
            goto terminate;                                                                                            \
        } else {                                                                                                       \
            vs_logger_set_loglev(prev_loglev);                                                                         \
        }                                                                                                              \
    } while (0)

calls_t calls;

static vs_netif_t *test_netif;

static const vs_device_manufacture_id_t manufacturer_id = {0};
static const vs_device_type_t device_type = {0};
static const vs_device_serial_t device_serial = {0};
static uint32_t device_roles = 0;
static const vs_sdmp_service_t *sdmp_fldt_server;
static const vs_sdmp_service_t *sdmp_fldt_client;

// static vs_update_file_type_t file_type_1 = {.type = 1};
// static vs_update_file_type_t file_type_2 = {.type = 1};
vs_mac_addr_t test_mac = {0};

/******************************************************************************/
static vs_status_e
_add_filetype(const vs_update_file_type_t *file_type, vs_update_interface_t **update_ctx) {
    switch (file_type->type) {
    case VS_UPDATE_FIRMWARE:
        *update_ctx = vs_firmware_update_ctx();
        break;
    case VS_UPDATE_TRUST_LIST:
        *update_ctx = vs_tl_update_ctx();
        break;
    default:
        VS_LOG_ERROR("Unsupported file type : %d", file_type->type);
        return VS_CODE_ERR_UNSUPPORTED_PARAMETER;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static void
_on_file_updated(vs_update_file_type_t *file_type,
                 const vs_file_version_t *prev_file_ver,
                 const vs_file_version_t *new_file_ver,
                 vs_update_interface_t *update_interface,
                 const vs_mac_addr_t *gateway,
                 bool successfully_updated) {
    char file_descr[512];
    const char *file_type_descr = NULL;

    VS_IOT_ASSERT(update_interface);
    VS_IOT_ASSERT(prev_file_ver);
    VS_IOT_ASSERT(new_file_ver);
    VS_IOT_ASSERT(gateway);

    if (VS_UPDATE_FIRMWARE == file_type->type) {
        file_type_descr = "firmware";
    } else {
        file_type_descr = "trust list";
    }

    VS_LOG_INFO(
            "New %s was loaded and %s : %s",
            file_type_descr,
            successfully_updated ? "successfully installed" : "did not installed successfully",
            update_interface->describe_version(
                    update_interface->storage_context, file_type, new_file_ver, file_descr, sizeof(file_descr), false));
    VS_LOG_INFO("Previous %s : %s",
                file_type_descr,
                update_interface->describe_version(update_interface->storage_context,
                                                   file_type,
                                                   prev_file_ver,
                                                   file_descr,
                                                   sizeof(file_descr),
                                                   false));
}

/**********************************************************/
static bool
test_fldt_initialize(void) {

    sdmp_fldt_server = vs_sdmp_fldt_server(&test_mac, _add_filetype);
    STATUS_CHECK(vs_sdmp_register_service(sdmp_fldt_server), "Cannot register FLDT server service");

    sdmp_fldt_client = vs_sdmp_fldt_client(_on_file_updated);
    STATUS_CHECK(vs_sdmp_register_service(sdmp_fldt_client), "Cannot register FLDT client service");

    return true;

terminate:

    return false;
}

/**********************************************************/
static bool
test_fldt_add_filetypes(void) {

    STATUS_CHECK(vs_fldt_server_add_file_type(vs_firmware_update_file_type(), vs_firmware_update_ctx(), false),
                 "Unable to add firmware file type");
    STATUS_CHECK(vs_fldt_server_add_file_type(vs_tl_update_file_type(), vs_tl_update_ctx(), false),
                 "Unable to add firmware file type");

    STATUS_CHECK(vs_fldt_client_add_file_type(vs_firmware_update_file_type(), vs_firmware_update_ctx()),
                 "Unable to add firmware file type");
    STATUS_CHECK(vs_fldt_client_add_file_type(vs_tl_update_file_type(), vs_tl_update_ctx()),
                 "Unable to add firmware file type");
terminate:

    return true;
}

///**********************************************************/
//// INFV : Inform New File Version
// static bool
// test_INFV(void){
//    vs_fldt_infv_new_file_request_t new_file;
//    vs_fldt_file_type_mapping_t client_file_type;
//
//    FLDT_CHECK_GOTO(vs_fldt_init_client(), true, "Unable to initialize FLDT as client");
//    FLDT_CHECK_GOTO(vs_fldt_init_server(server_add_filetype), true, "Unable to initialize FLDT as server");
//    vs_fldt_set_is_gateway(true);
//
//    client_file_type = make_client_mapping(&file_type_1);
//    FLDT_CHECK_GOTO(vs_fldt_update_client_file_type(&client_file_type), true, "Unable to add Firmware client file
//    mapping for the first time (vs_fldt_update_client_file_type call)");
//
//    VS_IOT_MEMSET(&new_file, 0, sizeof(new_file));
//    new_file.version.file_type = file_type_1;
//    new_file.version.major = 10;
//    new_file.version.timestamp = 2;
//    VS_IOT_MEMSET(&client_get_current_file_version, 0, sizeof(client_get_current_file_version));
//    client_get_current_file_version.file_type = file_type_1;
//    client_get_current_file_version.major = 9;
//    client_get_current_file_version.timestamp = 1;
//
//    calls.calls = 0;
//    FLDT_CHECK_GOTO(vs_fldt_broadcast_new_file(&new_file),
//            calls.client_set_gateway_mac && calls.client_get_current_version && calls.client_update_file,
//    "Unable to broadcast new file while client has older version (vs_fldt_broadcast_new_file call)");
//
//    client_get_current_file_version.major = 10;
//    client_get_current_file_version.timestamp = 2;
//
//    calls.calls = 0;
//    FLDT_CHECK_GOTO(vs_fldt_broadcast_new_file(&new_file),
//                    calls.client_set_gateway_mac && calls.client_get_current_version && !calls.client_update_file,
//                    "Unable to broadcast new file while client has the same one (vs_fldt_broadcast_new_file call)");
//
//    return true;
//
//    terminate:
//
//    return false;
//}
//
///**********************************************************/
//// GFTI : Get File Type Information
// static bool
// test_GFTI(void){
//    vs_fldt_gfti_fileinfo_request_t file_request;
//    vs_fldt_file_type_mapping_t client_file_type;
//
//    FLDT_CHECK_GOTO(vs_fldt_init_client(), true, "Unable to initialize FLDT as client");
//    FLDT_CHECK_GOTO(vs_fldt_init_server(server_add_filetype), true, "Unable to initialize FLDT as server");
//    vs_fldt_set_is_gateway(true);
//
//    client_file_type = make_client_mapping(&file_type_1);
//    FLDT_CHECK_GOTO(vs_fldt_update_client_file_type(&client_file_type), true, "Unable to add Firmware client file
//    mapping for the first time (vs_fldt_update_client_file_type call)");
//
//    VS_IOT_MEMCPY(&file_request.file_type, &client_file_type.file_type, sizeof(client_file_type.file_type));
//    VS_IOT_MEMSET(&server_get_version_file, 0, sizeof(server_get_version_file));
//    server_get_version_file.version.file_type = client_file_type.file_type;
//    server_get_version_file.version.major = 10;
//    server_get_version_file.version.timestamp = 10;
//
//    calls.calls = 0;
//    FLDT_CHECK_GOTO(vs_fldt_ask_file_type_info(&file_request),
//                    calls.server_version && calls.server_add_filetype && calls.client_get_current_version &&
//                    calls.client_got_info, "Unable to request gateway's file version which is the same as local one
//                    (vs_fldt_ask_file_type_info call)");
//
//    client_get_current_file_version.major = 9;
//    client_get_current_file_version.timestamp = 9;
//
//    calls.calls = 0;
//    FLDT_CHECK_GOTO(vs_fldt_ask_file_type_info(&file_request),
//                    calls.server_version && !calls.server_add_filetype && calls.client_get_current_version &&
//                    calls.client_got_info && calls.client_update_file, "Unable to request gateway's file version which
//                    is newer then local one (vs_fldt_ask_file_type_info call)");
//
//    return true;
//
//    terminate:
//
//    return false;
//}
//
///**********************************************************/
//// GNFH : Get New File Header
// static bool
// test_GNFH(void){
//    vs_fldt_gnfh_header_request_t request;
//
//    file_ver.file_type = make_client_mapping(&file_type_1).file_type;
//    request.version.file_type = file_ver.file_type;
//    calls.calls = 0;
//
//    FLDT_CHECK_GOTO(vs_fldt_ask_file_header(&mac_addr_server_call, &request),
//            calls.client_got_header && calls.server_header,
//            "Unable to get firmware header (vs_fldt_ask_file_header call)");
//
//    return true;
//
//    terminate:
//
//    return false;
//}
//
///**********************************************************/
//// GNFD : Get New File Data
// static bool
// test_GNFD(void){
//    vs_fldt_gnfd_data_request_t request;
//
//    file_ver.file_type = make_client_mapping(&file_type_1).file_type;
//    request.version.file_type = file_ver.file_type;
//    calls.calls = 0;
//
//    FLDT_CHECK_GOTO(vs_fldt_ask_file_data(&mac_addr_server_call, &request),
//                    calls.client_got_data && calls.server_data,
//                    "Unable to get firmware chunk (vs_fldt_ask_file_chunk call)");
//
//    return true;
//
//    terminate:
//
//    return false;
//}
//
///**********************************************************/
//// GNFF : Get New File Footer
// static bool
// test_GNFF(void){
//    vs_fldt_gnff_footer_request_t request;
//
//    file_ver.file_type = make_client_mapping(&file_type_1).file_type;
//    request.version.file_type = file_ver.file_type;
//    calls.calls = 0;
//
//    FLDT_CHECK_GOTO(vs_fldt_ask_file_footer(&mac_addr_server_call, &request),
//                    calls.client_got_footer && calls.server_footer,
//                    "Unable to get firmware footer (vs_fldt_ask_file_footer call)");
//
//    return true;
//
//    terminate:
//
//    return false;
//}

/**********************************************************/
uint16_t
vs_fldt_tests(vs_hsm_impl_t *hsm_impl) {
    uint16_t failed_test_result = 0;

    START_TEST("FLDT");

    vs_log_level_t logLevel = vs_logger_get_loglev();

    vs_logger_set_loglev(VS_LOGLEV_INFO);
    test_netif = vs_test_netif();
    TEST_CASE_OK("Prepare test",
                 vs_test_erase_otp_provision(hsm_impl) && vs_test_create_device_key(hsm_impl) &&
                         vs_test_create_test_hl_keys(hsm_impl) && vs_test_create_test_tl(hsm_impl));

    vs_logger_set_loglev(logLevel);

    SDMP_CHECK_GOTO(vs_sdmp_init(test_netif, manufacturer_id, device_type, device_serial, device_roles),
                    "vs_sdmp_init call");
    TEST_CASE_OK("register and initialize FLDT service", test_fldt_initialize());
    TEST_CASE_OK("Add file types", test_fldt_add_filetypes());
    //
    //    TEST_CASE_OK("Test broadcast \"Inform New File Version\" (INFV) call", test_INFV());
    //    TEST_CASE_OK("Test \"Get File Type Information\" (GFTI) call", test_GFTI());
    //    TEST_CASE_OK("Test \"Get New File Header\" (GNFH) call", test_GNFH());
    //    TEST_CASE_OK("Test \"Get New File Data\" (GNFD) call", test_GNFD());
    //    TEST_CASE_OK("Test \"Get New File Footer\" (GNFF) call", test_GNFF());

    SDMP_CHECK_GOTO(vs_sdmp_deinit(&test_netif), "vs_sdmp_deinit call");

terminate:

    vs_sdmp_deinit();

    return failed_test_result;
}
