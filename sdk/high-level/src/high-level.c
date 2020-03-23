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


#include <virgil/iot/high-level/high-level.h>
#include <virgil/iot/protocols/snap/info/info-server.h>
#include <virgil/iot/protocols/snap/prvs/prvs-server.h>
#include <virgil/iot/protocols/snap/fldt/fldt-server.h>
#include <virgil/iot/protocols/snap/cfg/cfg-server.h>
#include <virgil/iot/protocols/snap/fldt/fldt-client.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/provision/provision.h>


#if FLDT_SERVER || FLDT_CLIENT
#include <virgil/iot/firmware/firmware.h>
#endif // FLDT_SERVER || FLDT_CLIENT

#if FLDT_SERVER
static vs_status_e
_add_filetype(const vs_update_file_type_t *file_type, vs_update_interface_t **update_ctx);
#endif // FLDT_SERVER

#if FLDT_CLIENT
static void
_on_file_updated(vs_update_file_type_t *file_type,
                 const vs_file_version_t *prev_file_ver,
                 const vs_file_version_t *new_file_ver,
                 vs_update_interface_t *update_interface,
                 const vs_mac_addr_t *gateway,
                 bool successfully_updated);
#endif // FLDT_CLIENT

static void
_file_ver_info_cb(vs_file_version_t ver);

static vs_provision_events_t _provision_event = {_file_ver_info_cb};
static vs_iotkit_events_t _iotkit_events = {NULL};
static bool _sebox_present = false;

/******************************************************************************/
vs_status_e
vs_high_level_init(vs_device_manufacture_id_t manufacture_id,
                   vs_device_type_t device_type,
                   vs_device_serial_t serial,
                   uint32_t device_roles,
                   vs_secmodule_impl_t *secmodule_impl,
                   vs_storage_op_ctx_t *tl_storage_impl,
#if FLDT_SERVER || FLDT_CLIENT
                   vs_storage_op_ctx_t *firmware_storage_impl,
#endif // FLDT_SERVER || FLDT_CLIENT
                   vs_storage_op_ctx_t *secbox_storage_impl,
                   vs_netif_t *netif_impl[],
#if MSGR_SERVER
                   vs_snap_msgr_server_service_t msgr_server_cb,
#endif
#if MSGR_CLIENT
                   vs_snap_msgr_client_service_t msgr_client_cb,
#endif
#if CFG_SERVER
                   vs_snap_cfg_server_service_t cfg_server_cb,
#endif
                   vs_netif_process_cb_t packet_preprocessor_cb,
                   vs_iotkit_events_t iotkit_events) {
    vs_status_e res = VS_CODE_ERR_INIT_SNAP;
    vs_status_e ret_code;
    uint8_t i = 1;
    VS_IOT_ASSERT(secmodule_impl);
    VS_IOT_ASSERT(tl_storage_impl);
    VS_IOT_ASSERT(netif_impl);
    VS_IOT_ASSERT(netif_impl[0]);

    // Save callbacks
    _iotkit_events = iotkit_events;

    //
    // ---------- Initialize Virgil SDK modules ----------
    //

    // Provision module
    ret_code = vs_provision_init(tl_storage_impl, secmodule_impl, _provision_event);
    if (VS_CODE_OK != ret_code && VS_CODE_ERR_NOINIT != ret_code) {
        VS_LOG_ERROR("Cannot initialize Provision module");
        goto terminate;
    }

    // SecBox module if required
    if (secbox_storage_impl) {
        ret_code = vs_secbox_init(secbox_storage_impl, secmodule_impl);
        if (VS_CODE_OK != ret_code && VS_CODE_ERR_NOINIT != ret_code) {
            VS_LOG_ERROR("Cannot initialize SecBox module");
            goto terminate;
        }
        _sebox_present = true;
    }

#if FLDT_SERVER || FLDT_CLIENT
    // Firmware module
    vs_file_version_t ver;
    VS_IOT_ASSERT(firmware_storage_impl);
    STATUS_CHECK(vs_firmware_init(firmware_storage_impl, secmodule_impl, manufacture_id, device_type, &ver),
                 "Unable to initialize Firmware module");
#if INFO_SERVER
    vs_snap_info_set_firmware_ver(ver);
#endif // INFO_SERVER
#endif // FLDT_SERVER || FLDT_CLIENT

    // SNAP module
    STATUS_CHECK(vs_snap_init(netif_impl[0], packet_preprocessor_cb, manufacture_id, device_type, serial, device_roles),
                 "Unable to initialize SNAP module");


    while (netif_impl[i] != NULL) {
        STATUS_CHECK_RET(vs_snap_netif_add(netif_impl[i]), "Unable to add netif to a SNAP module");
        ++i;
    }

    //
    // ---------- Register SNAP services ----------
    //

#if INFO_SERVER
    //  INFO server service
    const vs_snap_service_t *snap_info_server;
    snap_info_server = vs_snap_info_server(NULL);
    STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO server service");
#endif // INFO_SERVER

#if CFG_SERVER
    const vs_snap_service_t *snap_cfg_server;
    snap_cfg_server = vs_snap_cfg_server(cfg_server_cb);
    STATUS_CHECK(vs_snap_register_service(snap_cfg_server), "Cannot register CFG server service");
#endif


#if PRVS_SERVER
    //  PRVS service
    const vs_snap_service_t *snap_prvs_server;
    snap_prvs_server = vs_snap_prvs_server(secmodule_impl);
    STATUS_CHECK(vs_snap_register_service(snap_prvs_server), "Cannot register PRVS service");
#endif // PRVS_SERVER


#if FLDT_SERVER
    //  FLDT server service
    const vs_snap_service_t *snap_fldt_server;
    vs_mac_addr_t mac;
    vs_snap_mac_addr(vs_snap_default_netif(), &mac);
    snap_fldt_server = vs_snap_fldt_server(&mac, _add_filetype);
    STATUS_CHECK(vs_snap_register_service(snap_fldt_server), "Cannot register FLDT server service");
    STATUS_CHECK(vs_fldt_server_add_file_type(vs_tl_update_file_type(), vs_tl_update_ctx(), false),
                 "Unable to add Trust List file type");
#endif // FLDT_SERVER

#if MSGR_SERVER
    const vs_snap_service_t *snap_msgr_server = vs_snap_msgr_server(msgr_server_cb);
    STATUS_CHECK(vs_snap_register_service(snap_msgr_server), "Cannot register MSGR server service");
#endif


#if FLDT_CLIENT
    //  FLDT client service
    const vs_snap_service_t *snap_fldt_client;
    snap_fldt_client = vs_snap_fldt_client(_on_file_updated);
    STATUS_CHECK(vs_snap_register_service(snap_fldt_client), "Cannot register FLDT client service");
    STATUS_CHECK(vs_fldt_client_add_file_type(vs_firmware_update_file_type(), vs_firmware_update_ctx()),
                 "Unable to add firmware file type");
    STATUS_CHECK(vs_fldt_client_add_file_type(vs_tl_update_file_type(), vs_tl_update_ctx()),
                 "Unable to add firmware file type");
#endif // FLDT_CLIENT

#if MSGR_CLIENT
    const vs_snap_service_t *snap_msgr_client = vs_snap_msgr_client(msgr_client_cb);
    STATUS_CHECK(vs_snap_register_service(snap_msgr_client), "Cannot register MSGR client service");
#endif

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
#if FLDT_SERVER
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
#endif // FLDT_SERVER


/******************************************************************************/
#if FLDT_CLIENT
static void
_on_file_updated(vs_update_file_type_t *file_type,
                 const vs_file_version_t *prev_file_ver,
                 const vs_file_version_t *new_file_ver,
                 vs_update_interface_t *update_interface,
                 const vs_mac_addr_t *gateway,
                 bool successfully_updated) {

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

    VS_LOG_INFO("New %s was loaded and %s : %u.%u.%ull.%ull",
                file_type_descr,
                successfully_updated ? "successfully installed" : "did not installed successfully",
                (unsigned)new_file_ver->major,
                (unsigned)new_file_ver->minor,
                (unsigned long long)new_file_ver->patch,
                (unsigned long long)new_file_ver->build);


    if (file_type->type == VS_UPDATE_FIRMWARE && successfully_updated) {
        if (_iotkit_events.reboot_request_cb) {
            _iotkit_events.reboot_request_cb();
        }
    }
}
#endif // FLDT_CLIENT

/******************************************************************************/
vs_status_e
vs_high_level_deinit(void) {

    // Deinit Virgil SDK modules
    vs_snap_deinit();

#if FLDT_SERVER || FLDT_CLIENT
    // Deinit firmware
    vs_firmware_deinit();
#endif // FLDT_SERVER

    // Deinit provision
    vs_provision_deinit();

    // Deinit SecBox
    if (_sebox_present) {
        vs_secbox_deinit();
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static void
_file_ver_info_cb(vs_file_version_t ver) {
    vs_snap_info_set_tl_ver(ver);
}

/******************************************************************************/
