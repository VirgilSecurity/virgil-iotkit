#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_spi_flash.h"
#include "esp_system.h"
#include "esp_wifi.h"

#include "threads/main-thread.h"
#include "threads/message-bin-thread.h"
#include "threads/file-download-thread.h"

#include "sdkconfig.h"
#include <stdio.h>
#include <string.h>

#include <platform/init/idf/flash_nvs.h>
#include <platform/init/idf/flash_data.h>
#include <platform/init/idf/udp_socket.h>
#include <platform/init/idf/wifi_network.h>

// implementation
#include <defaults/netif/netif-udp-broadcast.h>
#include <defaults/netif/packets-queue.h>
#include <defaults/storage/storage-esp-impl.h>
#include <defaults/storage/nvs-storage-esp-impl.h>
#include <defaults/vs-soft-secmodule/vs-soft-secmodule.h>
#include <defaults/cloud/thing-service/esp-http.h>
#include <virgil/iot/vs-aws-message-bin/aws-message-bin.h>

// Modules
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/info/info-server.h>
#include <virgil/iot/protocols/snap/prvs/prvs-server.h>
#include <virgil/iot/high-level/high-level.h>

#include <update-config.h>

static vs_status_e
app_start(void);

static void
wifi_status_cb(bool ready);

static vs_status_e
start_wifi(wifi_config_t wifi_config);

static void
_on_file_updated(vs_update_file_type_t *file_type,
                 const vs_file_version_t *prev_file_ver,
                 const vs_file_version_t *new_file_ver,
                 vs_update_interface_t *update_interface,
                 const vs_mac_addr_t *gateway,
                 bool successfully_updated) {
}

vs_iotkit_events_t iotkit_events = {.reboot_request_cb = NULL};

// Implementation variables
static vs_secmodule_impl_t *secmodule_impl = NULL;
static vs_netif_t *netifs_impl[2] = {NULL, NULL};
static vs_storage_op_ctx_t tl_storage_impl;
static vs_storage_op_ctx_t slots_storage_impl;
static vs_storage_op_ctx_t fw_storage_impl;

// Device parameters
static vs_device_manufacture_id_t manufacture_id = "VIRGIL_ESP32";
static vs_device_type_t device_type = "DVB";
static vs_device_serial_t serial;

//******************************************************************************
void
app_main(void) {
    wifi_config_t wifi_config = {
            .sta = {.ssid = ESP_WIFI_SSID, .password = ESP_WIFI_PASS},
    };

    vTaskDelay(1000 / portTICK_PERIOD_MS);
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Initialize NVS
    VS_LOG_INFO("Initialization NVS flash");
    INIT_STATUS_CHECK(flash_nvs_init(), "NVC Error");
    INIT_STATUS_CHECK(flash_nvs_get_serial(serial), "Error read device serial");

    // Init device object
    vs_device_ctx_init(manufacture_id, device_type);

    if (VS_CODE_OK != start_wifi(wifi_config)) {
        VS_LOG_ERROR("Error to start wifi");
    }

    while (xEventGroupWaitBits(vs_device_ctx()->shared_events, WIFI_INIT_BIT, pdFALSE, pdTRUE, portMAX_DELAY) == 0) {
    }

    if (VS_CODE_OK != app_start()) {
        goto terminate;
    }

    while (1) {
        vTaskDelay(30000 / portTICK_PERIOD_MS);
    }

terminate:
    VS_LOG_ERROR("Application start error");

    // De-initialize IoTKit internals
    vs_high_level_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();

    vs_packets_queue_deinit();

    while (1) {
        vTaskDelay(30000 / portTICK_PERIOD_MS);
    }
}

//******************************************************************************
static vs_status_e
app_start(void) {
    vs_file_version_t ver;
    vs_status_e res = VS_CODE_ERR_NOINIT;
    //
    // ---------- Create implementations ----------
    //

    //  Network interface
    VS_LOG_DEBUG("Initialization netif");
    vs_packets_queue_init(vs_snap_default_processor);
    netifs_impl[0] = vs_hal_netif_udp_bcast();

    // Prepare local storage
    STATUS_CHECK(vs_app_init_partition(ESP_HSM_PARTITION_NAME), "Cannot initialize HSM partition");
    STATUS_CHECK(vs_app_init_partition(ESP_FW_STORAGE_PARTITION_NAME), "Cannot initialize FW partition");

    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(
            vs_app_nvs_storage_init_impl(&slots_storage_impl, vs_app_nvs_slots_namespace(), VS_SLOTS_STORAGE_MAX_SIZE),
            "Cannot create Slots storage");

    // Firmware storage
    STATUS_CHECK(vs_app_storage_init_impl(&fw_storage_impl, vs_app_firmware_dir(), VS_MAX_FIRMWARE_UPDATE_SIZE),
                 "Cannot create FW storage");

    // Soft Security Module
    secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

    // Cloud module
    STATUS_CHECK(vs_cloud_init(vs_esp_http_impl(), vs_aws_message_bin_impl(), secmodule_impl),
                 "Unable to initialize Cloud module");

    // Register message bin default handlers
    STATUS_CHECK(vs_message_bin_register_handlers(), "Unable to register message bin handlers");

    //
    // ---------- Initialize Virgil SDK modules ----------
    //
    STATUS_CHECK(vs_high_level_init(manufacture_id,
                                    device_type,
                                    serial,
                                    VS_SNAP_DEV_THING,
                                    secmodule_impl,
                                    &tl_storage_impl,
                                    netifs_impl,
                                    vs_packets_queue_add,
                                    iotkit_events),
                 "Cannot initialize IoTKit");

    STATUS_CHECK(vs_firmware_init(&fw_storage_impl, secmodule_impl, manufacture_id, device_type, &ver),
                 "Unable to initialize Firmware module");

    // Send broadcast notification about self start
    vs_snap_info_start_notification(vs_snap_netif_routing());

    // Start app
    vs_main_start_threads();

    res = VS_CODE_OK;

terminate:
    return res;
}

/******************************************************************************/
static vs_status_e
start_wifi(wifi_config_t wifi_config) {
    // Start WiFi
    VS_LOG_INFO("Start WiFi");
    if (ESP_OK != wifi_init_sta(wifi_status_cb, wifi_config)) {
        VS_LOG_WARNING("Cannot initialize WiFi STA");
        return VS_CODE_ERR_INCORRECT_PARAMETER;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static void
wifi_status_cb(bool ready) {
    if (ready) {
        VS_LOG_DEBUG("WiFi status ready");
        xEventGroupSetBits(vs_device_ctx()->shared_events, WIFI_INIT_BIT);
    } else {
        VS_LOG_DEBUG("WiFi status  not ready");
        xEventGroupClearBits(vs_device_ctx()->shared_events, WIFI_INIT_BIT);
        vs_hal_netif_udp_bcast_set_active(false);
        vs_packets_queue_enable_heart_beat(false);
        return;
    }

    // Initialize UDP
    udp_socket_init(4100, 1024);

    // Activate network interface
    vs_hal_netif_udp_bcast_set_active(true);
    vs_packets_queue_enable_heart_beat(true);
}

/******************************************************************************/
void
vs_impl_msleep(size_t msec) {
    vTaskDelay(msec / portTICK_PERIOD_MS);
}

/******************************************************************************/
void
vs_impl_device_serial(vs_device_serial_t serial_number) {
    memcpy(serial_number, vs_snap_device_serial(), VS_DEVICE_SERIAL_SIZE);
}
