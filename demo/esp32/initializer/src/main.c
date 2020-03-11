#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_spi_flash.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include <stdio.h>
#include <string.h>

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

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

// Modules
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/info/info-server.h>
#include <virgil/iot/protocols/snap/prvs/prvs-server.h>
#include <virgil/iot/high-level/high-level.h>

#define CONFIG_EXAMPLE_IPV4
#define UDP_BROADCAST_PORT 4100
#define GPIO_LED GPIO_NUM_2

static void
_initializer_exec_task(void *pvParameters);

static void
wifi_status_cb(bool ready);

static vs_status_e
start_wifi(wifi_config_t wifi_config);

//******************************************************************************
void
app_main(void) {
    xTaskCreate(_initializer_exec_task, "_initializer_task", 8 * 4096, NULL, 5, NULL);
    while (1) {
        vTaskDelay(30000 / portTICK_PERIOD_MS);
    }
}

//******************************************************************************
static void
_initializer_exec_task(void *pvParameters) {
    vs_iotkit_events_t iotkit_events = {.reboot_request_cb = NULL};

    // Implementation variables
    vs_secmodule_impl_t *secmodule_impl = NULL;
    vs_netif_t *netifs_impl[2] = {NULL, NULL};
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t slots_storage_impl;

    // Device parameters
    vs_device_manufacture_id_t manufacture_id = "VIRGIL_ESP32";
    vs_device_type_t device_type = "DVB";
    vs_device_serial_t serial;
    // Device specific parameters
#if GATEWAY
    uint32_t device_roles = (uint32_t)VS_SNAP_DEV_GATEWAY | (uint32_t)VS_SNAP_DEV_INITIALIZER;
#else
    uint32_t device_roles = (uint32_t)VS_SNAP_DEV_THING | (uint32_t)VS_SNAP_DEV_INITIALIZER;
#endif

    vTaskDelay(1000 / portTICK_PERIOD_MS);
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Initialize NVS
    VS_LOG_INFO("Initialization NVS flash");
    INIT_STATUS_CHECK(flash_nvs_init(), "NVC Error");
    INIT_STATUS_CHECK(flash_nvs_get_serial(serial), "Error read device serial");

    //
    // ---------- Create implementations ----------
    //

    //  Network interface
    VS_LOG_DEBUG("Initialization netif");
    wifi_config_t wifi_config = {
            .sta = {.ssid = ESP_WIFI_SSID, .password = ESP_WIFI_PASS},
    };
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

    // Soft Security Module
    secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

    //
    // ---------- Initialize Virgil SDK modules ----------
    //
    STATUS_CHECK(vs_high_level_init(manufacture_id,
                                    device_type,
                                    serial,
                                    device_roles,
                                    secmodule_impl,
                                    &tl_storage_impl,
                                    netifs_impl,
                                    vs_packets_queue_add,
                                    iotkit_events),
                 "Cannot initialize IoTKit");

    if (VS_CODE_OK != start_wifi(wifi_config)) {
        VS_LOG_ERROR("Error to start wifi");
    }

    while (1) {
        vTaskDelay(30000 / portTICK_PERIOD_MS);
    }

terminate:
    VS_LOG_INFO("Application start error");

    // De-initialize IoTKit internals
    vs_high_level_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();

    vs_packets_queue_deinit();

    while (1) {
        vTaskDelay(30000 / portTICK_PERIOD_MS);
    }
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
    if (!ready) {
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
