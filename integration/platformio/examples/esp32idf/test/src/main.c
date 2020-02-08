#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "sdkconfig.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include <platform/init/idf/flash_nvs.h>
#include <platform/init/idf/wifi_network.h>
#include <platform/init/idf/udp_socket.h>

// implementation
#include <defaults/netif/netif-udp-broadcast.h>
#include <defaults/vs-soft-secmodule/vs-soft-secmodule.h>
#include <defaults/storage/storage-esp-impl.h>

// Modules
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/tests/tests.h>

#include <trust_list-config.h>

#define CONFIG_EXAMPLE_IPV4
#define UDP_BROADCAST_PORT 4100

static void 
_test_exec_task(void *pvParameters);

//******************************************************************************
void app_main(void) {
    // Device parameters
    vs_device_manufacture_id_t manufacture_id = "TEST_ESP32";
    vs_device_type_t device_type = "DVB";
    vs_device_serial_t serial;
 
    // // Network
    // wifi_config_t wifi_config = {
    //     .sta = {.ssid = ESP_WIFI_SSID, .password = ESP_WIFI_PASS},
    // };
    // vs_netif_t *netif_impl = NULL;

    VS_IOT_MEMSET(serial, 0x03, sizeof(serial));

    vs_logger_init(VS_LOGLEV_DEBUG);

    // Initialize NVS
    VS_LOG_INFO("Initialization NVS flash");
    INIT_STATUS_CHECK(flash_nvs_init(), "NVC Error");

    // // Initialize WiFi
    // VS_LOG_INFO("Configuring WiFi");
    // INIT_STATUS_CHECK(wifi_init_sta(wifi_config), "WIFI Error");
    // VS_LOG_INFO("Waiting for AP connection...");
    // wifi_ready_wait(portMAX_DELAY);

    // // Initialize UDP
    // VS_LOG_INFO("Create UDP listener");
    // udp_socket_init(4100, 128);

    //
    // ---------- Create implementations ----------
    //

    // // Initialization netif
    // VS_LOG_DEBUG("Initialization netif");
    // netif_impl = vs_hal_netif_udp_bcast();

 
    // VS_LOG_DEBUG("Initialization snap");
    // STATUS_CHECK(vs_snap_init(netif_impl, manufacture_id, device_type, serial, device_roles), "Unable to initialize SNAP module");

    // //
    // // ---------- Register SNAP services ----------
    // //

    // //  INFO server service
    // VS_LOG_DEBUG("Initialization snap info server");
    // snap_info_server = vs_snap_info_server(NULL);
    // VS_LOG_DEBUG("Register snap info server");
    // STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO server service");

    // //  PRVS service
    // VS_LOG_DEBUG("Initialization snap prvs service");
    // snap_prvs_server = vs_snap_prvs_server(secmodule_impl);
    // VS_LOG_DEBUG("Register snap prvs service");
    // STATUS_CHECK(vs_snap_register_service(snap_prvs_server), "Cannot register PRVS service");

    //start tests
    xTaskCreate(_test_exec_task, "test_task", 8 * 4096, NULL, 5, NULL);

terminate:
    while (1);
}

//******************************************************************************
static void 
_test_exec_task(void *pvParameters) {
    int res = -1;
    vs_status_e ret_code;
    vs_secmodule_impl_t *secmodule_impl = NULL;
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t slots_storage_impl;

    // Prepare local storage
    STATUS_CHECK(vs_app_prepare_storage("test"), "Cannot prepare storage");

    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(vs_app_storage_init_impl(&slots_storage_impl, vs_app_slots_dir(), VS_SLOTS_STORAGE_MAX_SIZE),
                 "Cannot create Slots storage");

     // Soft Security Module
    secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

   // Provision module
    VS_LOG_DEBUG("Initialization provision module");
    ret_code = vs_provision_init(&tl_storage_impl, secmodule_impl);
    if (VS_CODE_OK != ret_code && VS_CODE_ERR_NOINIT != ret_code) {
        VS_LOG_ERROR("Cannot initialize Provision module");
        goto terminate;
    }

    res = vs_crypto_test(secmodule_impl);

terminate:
    VS_LOG_INFO("test result = %d", res);

    vTaskDelay(1000 / portTICK_PERIOD_MS);
    
    // Deinit provision
    vs_provision_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();
    VS_LOG_INFO("Application terminate");

    vTaskDelete(NULL);
}