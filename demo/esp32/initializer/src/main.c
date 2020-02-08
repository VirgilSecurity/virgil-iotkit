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
#include "esp_task_wdt.h"
#include "driver/gpio.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include <platform/init/idf/flash_nvs.h>
#include <platform/init/idf/wifi_network.h>
#include <platform/init/idf/udp_socket.h>

// implementation
#include <defaults/netif/netif-udp-broadcast.h>
#include <defaults/netif/netif-ble.h>
#include <defaults/netif/packets-queue.h>
#include <defaults/vs-soft-secmodule/vs-soft-secmodule.h>
#include <defaults/storage/storage-esp-impl.h>

// Modules
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/cfg/cfg-server.h>
#include <virgil/iot/protocols/snap/info/info-server.h>
#include <virgil/iot/protocols/snap/prvs/prvs-server.h>

#define CONFIG_EXAMPLE_IPV4
#define UDP_BROADCAST_PORT 4100
#define GPIO_LED GPIO_NUM_2

static void
_initializer_exec_task(void *pvParameters);

#define TWDT_TIMEOUT_S 5

static vs_status_e
vs_snap_cfg_config(const vs_cfg_configuration_t *configuration);

static void
wifi_status_cb(bool ready);

static vs_status_e
start_wifi(void);

//******************************************************************************
void
app_main(void) {
    xTaskCreate(_initializer_exec_task, "_initializer_task", 20 * 4096, NULL, 5, NULL);
    while (1)
        ;
}

//******************************************************************************
static void
_initializer_exec_task(void *pvParameters) {

    int i = 0;

    vs_logger_init(VS_LOGLEV_DEBUG);

    // Initialize LED GPIO
    gpio_set_direction(GPIO_LED, GPIO_MODE_OUTPUT);

    while (1) {
        VS_LOG_INFO("Loop print logging %d ...", i++);
        vTaskDelay(1000 / portTICK_PERIOD_MS);

        gpio_set_level(GPIO_LED, i % 2);

        if (i > 1) {
            continue;
        }

        vs_status_e ret_code;
        const vs_snap_service_t *snap_cfg_server;
        const vs_snap_service_t *snap_info_server;
        const vs_snap_service_t *snap_prvs_server;

        vs_storage_op_ctx_t slots_storage_impl;
        vs_storage_op_ctx_t tl_storage_impl;

        // Device parameters
        vs_device_manufacture_id_t manufacture_id = "TEST_ESP32";
        vs_device_type_t device_type = "DVB";
        vs_device_serial_t serial;
        vs_secmodule_impl_t *secmodule_impl = NULL;
        // Device specific parameters
#if GATEWAY
        uint32_t device_roles = (uint32_t)VS_SNAP_DEV_GATEWAY | (uint32_t)VS_SNAP_DEV_INITIALIZER;
#else
        uint32_t device_roles = (uint32_t)VS_SNAP_DEV_THING | (uint32_t)VS_SNAP_DEV_INITIALIZER;
#endif


        vs_netif_t *netif_udp_impl = NULL;
        vs_netif_t *netif_ble_impl = NULL;

        VS_IOT_MEMSET(serial, 0x03, sizeof(serial));

        // Initialize NVS
        VS_LOG_INFO("Initialization NVS flash");
        INIT_STATUS_CHECK(flash_nvs_init(), "NVS Error");

        //
        // ---------- Create implementations ----------
        //

        // Initialization netif
        VS_LOG_DEBUG("Initialization netif");
        vs_packets_queue_init(vs_snap_default_processor);
        netif_udp_impl = vs_hal_netif_udp_bcast();
        netif_ble_impl = vs_hal_netif_ble("VS-DEMO");


#if 0
    // Prepare local storage
    VS_LOG_DEBUG("Initialization Storage 1");
    STATUS_CHECK(vs_app_prepare_storage("test"), "Cannot prepare storage");

    // TrustList storage
    VS_LOG_DEBUG("Initialization Storage 2");
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    VS_LOG_DEBUG("Initialization Storage 3");
    STATUS_CHECK(vs_app_storage_init_impl(&slots_storage_impl, vs_app_slots_dir(), VS_SLOTS_STORAGE_MAX_SIZE),
                 "Cannot create Slots storage");

    // Soft Security Module
    VS_LOG_DEBUG("Initialization Soft Security Module");
    secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);
    // TrustList storage
    // Slots storage

    //
    // ---------- Initialize Virgil SDK modules ----------
    //

    // Provision module
    VS_LOG_DEBUG("Initialization provision module");
    ret_code = vs_provision_init(&tl_storage_impl, secmodule_impl);
    if (VS_CODE_OK != ret_code && VS_CODE_ERR_NOINIT != ret_code) {
        VS_LOG_ERROR("Cannot initialize Provision module");
        goto terminate;
    }

#endif

        VS_LOG_DEBUG("Initialization snap");
        STATUS_CHECK(
                vs_snap_init(netif_udp_impl, vs_packets_queue_add, manufacture_id, device_type, serial, device_roles),
                "Unable to initialize SNAP module");

        VS_LOG_DEBUG("Add BLE network interface");
        STATUS_CHECK(vs_snap_netif_add(netif_ble_impl), "Unable to add BLE network interface");


        //
        // ---------- Register SNAP services ----------
        //

        //  INFO server service
        VS_LOG_DEBUG("Initialization snap info server");
        snap_info_server = vs_snap_info_server(NULL);
        VS_LOG_DEBUG("Register snap info server");
        STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO server service");

        //  CFG server service
        VS_LOG_DEBUG("Initialization snap cfg server");
        snap_cfg_server = vs_snap_cfg_server(vs_snap_cfg_config);
        VS_LOG_DEBUG("Register snap cfg server");
        STATUS_CHECK(vs_snap_register_service(snap_cfg_server), "Cannot register _CFG server service");

        // Try to start WiFi
        start_wifi();
    }

terminate:;

#if 0
    //  PRVS service
    VS_LOG_DEBUG("Initialization snap prvs service");
    snap_prvs_server = vs_snap_prvs_server(secmodule_impl);
    VS_LOG_DEBUG("Register snap prvs service");
    STATUS_CHECK(vs_snap_register_service(snap_prvs_server), "Cannot register PRVS service");

    vTaskDelay(1000 / portTICK_PERIOD_MS);

    while (1);
terminate:
    VS_LOG_INFO("Application start error");
     // Deinit Virgil SDK modules
    vs_snap_deinit();

    // Deinit provision
    vs_provision_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();

    while (1);
#endif
}

/******************************************************************************/
static vs_status_e
start_wifi(void) {
    // Start WiFi
    VS_LOG_INFO("Start WiFi");
    if (ESP_OK != wifi_init_sta(wifi_status_cb)) {
        VS_LOG_WARNING("Cannot initialize WiFi STA");
        return VS_CODE_ERR_INCORRECT_PARAMETER;
    }
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
vs_snap_cfg_config(const vs_cfg_configuration_t *configuration) {
    CHECK_NOT_ZERO_RET(configuration, VS_CODE_ERR_INCORRECT_ARGUMENT);
    VS_LOG_DEBUG("Configure :");
    VS_LOG_DEBUG("     ssid : %s", configuration->ssid);
    VS_LOG_DEBUG("     pass : %s", configuration->pass);
    VS_LOG_DEBUG("     account : %s", configuration->account);

    if (strnlen((char *)configuration->ssid, 64) >= SSID_SZ) {
        VS_LOG_WARNING("Incorrect size of SSID");
        return VS_CODE_ERR_INCORRECT_PARAMETER;
    }

    if (strnlen((char *)configuration->pass, 64) >= PASS_SZ) {
        VS_LOG_WARNING("Incorrect size of Password");
        return VS_CODE_ERR_INCORRECT_PARAMETER;
    }

    // Save configuration
    if (ESP_OK != wifi_creds_save((char *)configuration->ssid, (char *)configuration->pass)) {
        VS_LOG_WARNING("Cannot save WiFi credentials");
        return VS_CODE_ERR_USER;
    }

    return start_wifi();
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

/******************************************************************************/
