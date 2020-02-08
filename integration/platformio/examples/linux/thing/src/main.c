

#include "config/update-config.h"
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/status_code/status_code.h>
#include "virgil/iot/provision/provision.h"
#include "virgil/iot/firmware/firmware.h"
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/fldt/fldt-client.h>
#include <virgil/iot/protocols/snap/info/info-server.h>
#include <defaults/firmware/firmware-nix-impl.h>
#include <defaults/vs-soft-secmodule/vs-soft-secmodule.h>

//#include "helpers/app-storage.h"
//#include "helpers/app-helpers.h"

#define THING_MANUFACTURE_ID 
#define THING_DEVICE_MODEL

// SNAP services
vs_snap_service_t *snap_info_server;
vs_snap_service_t *snap_fldt_client;

// Device parameters
vs_device_serial_t serial = {0};
vs_device_manufacture_id_t manufacture_id = {0};
vs_device_type_t device_type = {0};
vs_mac_addr_t forced_mac_addr;

// Implementation variables
vs_secmodule_impl_t *secmodule_impl = NULL;
vs_netif_t *netif_impl = NULL;
vs_storage_op_ctx_t tl_storage_impl;
vs_storage_op_ctx_t slots_storage_impl;
vs_storage_op_ctx_t fw_storage_impl;

static void _on_file_updated(vs_update_file_type_t *file_type,
                 const vs_file_version_t *prev_file_ver,
                 const vs_file_version_t *new_file_ver,
                 vs_update_interface_t *update_interface,
                 const vs_mac_addr_t *gateway,
                 bool successfully_updated) {
}

/******************************************************************************/
int main()
{
// Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);

 // Prepare device parameters
    VS_IOT_MEMSET(&serial, 0x03, sizeof(serial));
    VS_IOT_MEMSET(manufacture_id,22,sizeof(vs_device_manufacture_id_t));
    VS_IOT_MEMSET(device_type,66,sizeof(vs_device_type_t));
   
    
    // Set device info path ???
    vs_firmware_nix_set_info("BB", manufacture_id, device_type);
    


    // Prepare local storage
    VS_IOT_MEMSET(forced_mac_addr.bytes,55,6);
    STATUS_CHECK(vs_app_prepare_storage("thing", forced_mac_addr), "Cannot prepare storage");    

    //
    // ---------- Create implementations ----------
    //

    // Network interface
    netif_impl = vs_app_create_netif_impl(forced_mac_addr);

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
    // ---------- Initialize Virgil SDK modules ----------
    //

    // Provision module
    STATUS_CHECK(vs_provision_init(&tl_storage_impl, secmodule_impl), "Cannot initialize Provision module");

    // Firmware module
    STATUS_CHECK(vs_firmware_init(&fw_storage_impl, secmodule_impl, manufacture_id, device_type),
                 "Unable to initialize Firmware module");

    // SNAP module
    STATUS_CHECK(vs_snap_init(netif_impl, manufacture_id, device_type, serial, VS_SNAP_DEV_THING),
                 "Unable to initialize SNAP module");


    //
    // ---------- Register SNAP services ----------
    //

    //  INFO server service
    snap_info_server = vs_snap_info_server(&tl_storage_impl, &fw_storage_impl, NULL);
    STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO server service");

    //  FLDT client service
    snap_fldt_client = vs_snap_fldt_client(_on_file_updated);
    STATUS_CHECK(vs_snap_register_service(snap_fldt_client), "Cannot register FLDT client service");
    STATUS_CHECK(vs_fldt_client_add_file_type(vs_firmware_update_file_type(), vs_firmware_update_ctx()),
                 "Unable to add firmware file type");
    STATUS_CHECK(vs_fldt_client_add_file_type(vs_tl_update_file_type(), vs_tl_update_ctx()),
                 "Unable to add firmware file type");


    VS_LOG_INFO("Starting thing");

    terminate:

    VS_LOG_INFO("\n\n\n");
    VS_LOG_INFO("Terminating application ...");

    // Deinitialize Virgil SDK modules
    vs_snap_deinit();

    // Deinit firmware
    vs_firmware_deinit();

    // Deinit provision
    vs_provision_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();

    //res = vs_firmware_nix_update(argc, argv);

    while(1);

}
