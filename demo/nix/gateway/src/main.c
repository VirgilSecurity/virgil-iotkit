//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include <unistd.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/high-level/high-level.h>
#include <virgil/iot/vs-curl-http/curl-http.h>
#include <virgil/iot/vs-soft-secmodule/vs-soft-secmodule.h>
#include <trust_list-config.h>
#include <update-config.h>
#include "threads/main-thread.h"
#include "helpers/app-helpers.h"
#include "helpers/file-cache.h"
#include "helpers/app-storage.h"
#include "sdk-impl/firmware/firmware-nix-impl.h"
#include <virgil/iot/vs-aws-message-bin/aws-message-bin.h>
#include <threads/message-bin-thread.h>
#include <virgil/iot/protocols/snap/info/info-server.h>

/******************************************************************************/
int
main(int argc, char *argv[]) {
    vs_mac_addr_t forced_mac_addr;
    vs_iotkit_events_t iotkit_events = {.reboot_request_cb = NULL};
    int res = -1;

    // Implementation variables
    vs_secmodule_impl_t *secmodule_impl = NULL;
    vs_netif_t *netifs_impl[2] = {NULL, NULL};
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t slots_storage_impl;
    vs_storage_op_ctx_t fw_storage_impl;

    // Device parameters
    vs_device_manufacture_id_t manufacture_id = {0};
    vs_device_type_t device_type = {0};
    vs_device_serial_t serial = {0};

    // Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Get input parameters
    STATUS_CHECK(vs_app_get_mac_from_commandline_params(argc, argv, &forced_mac_addr), "Cannot read input parameters");

    // Prepare device parameters
    vs_app_get_serial(serial, forced_mac_addr);
    vs_app_str_to_bytes(manufacture_id, GW_MANUFACTURE_ID, VS_DEVICE_MANUFACTURE_ID_SIZE);
    vs_app_str_to_bytes(device_type, GW_DEVICE_MODEL, VS_DEVICE_TYPE_SIZE);

    // Set device info path
    vs_firmware_nix_set_info(argv[0], manufacture_id, device_type);

    // Print title
    vs_app_print_title("Gateway", argv[0], GW_MANUFACTURE_ID, GW_DEVICE_MODEL);

    // Prepare local storage
    STATUS_CHECK(vs_app_prepare_storage("gateway", forced_mac_addr), "Cannot prepare storage");

    // Enable cached file IO
    vs_file_cache_enable(true);

    //
    // ---------- Create implementations ----------
    //

    // Network interface
    netifs_impl[0] = vs_app_create_netif_impl(forced_mac_addr);

    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(vs_app_storage_init_impl(&slots_storage_impl, vs_app_slots_dir(), VS_SLOTS_STORAGE_MAX_SIZE),
                 "Cannot create TrustList storage");

    // Firmware storage
    STATUS_CHECK(vs_app_storage_init_impl(&fw_storage_impl, vs_app_firmware_dir(), VS_MAX_FIRMWARE_UPDATE_SIZE),
                 "Cannot create TrustList storage");

    // Soft Security Module
    secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

    //
    // ---------- Initialize IoTKit internals ----------
    //

    // Cloud module
    STATUS_CHECK(vs_cloud_init(vs_curl_http_impl(), vs_aws_message_bin_impl(), secmodule_impl),
                 "Unable to initialize Cloud module");

    // Register message bin default handlers
    STATUS_CHECK(vs_message_bin_register_handlers(), "Unable to register message bin handlers");

    // Initialize IoTKit
    STATUS_CHECK(vs_high_level_init(manufacture_id,
                                    device_type,
                                    serial,
                                    VS_SNAP_DEV_GATEWAY,
                                    secmodule_impl,
                                    &tl_storage_impl,
                                    &fw_storage_impl,
                                    netifs_impl,
                                    iotkit_events),
                 "Cannot initialize IoTKit");

    //
    // ---------- Application work ----------
    //

    // Init gateway object
    vs_gateway_ctx_init(&forced_mac_addr);

    // Start app
    vs_main_start_threads();

    // Send broadcast notification about self start
    vs_snap_info_start_notification(NULL);

    // Sleep until CTRL_C
    vs_app_sleep_until_stop();


    //
    // ---------- Terminate application ----------
    //

terminate:

    VS_LOG_INFO("\n\n\n");
    VS_LOG_INFO("Terminating application ...");

    // De-initialize IoTKit internals
    vs_high_level_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();

    res = vs_firmware_nix_update(argc, argv);

    // Clean File cache
    vs_file_cache_clean();

    return res;
}

/******************************************************************************/
void
vs_impl_msleep(size_t msec) {
    usleep(msec * 1000);
}

/******************************************************************************/
void
vs_impl_device_serial(vs_device_serial_t serial_number) {
    memcpy(serial_number, vs_snap_device_serial(), VS_DEVICE_SERIAL_SIZE);
}

/******************************************************************************/
