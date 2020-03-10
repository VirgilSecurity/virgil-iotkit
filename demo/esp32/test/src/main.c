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
#include <defaults/netif/packets-queue.h>
#include <defaults/vs-soft-secmodule/vs-soft-secmodule.h>
#include <defaults/storage/storage-esp-impl.h>
#include <defaults/storage/nvs-storage-esp-impl.h>

// Modules
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/tests/tests.h>

#include <trust_list-config.h>

//******************************************************************************
void
app_main(void) {
    int res = -1;
    vs_provision_events_t _provision_event = {.tl_ver_info_cb = NULL};

    vs_status_e ret_code;
    vs_secmodule_impl_t *secmodule_impl = NULL;
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t slots_storage_impl;

    // Device parameters
    // vs_device_manufacture_id_t manufacture_id = "TEST_ESP32";
    // vs_device_type_t device_type = "DVB";
    vs_device_serial_t serial;

    VS_IOT_MEMSET(serial, 0x03, sizeof(serial));

    vs_logger_init(VS_LOGLEV_DEBUG);
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    // Initialize NVS
    VS_LOG_INFO("Initialization NVS flash");
    INIT_STATUS_CHECK(flash_nvs_init(), "NVC Error");

    // Prepare local storage
    STATUS_CHECK(vs_app_init_partition(ESP_FW_STORAGE_PARTITION_NAME), "Cannot initialize FW partition");
    STATUS_CHECK(vs_app_init_partition(ESP_HSM_PARTITION_NAME), "Cannot initialize HSM partition");

    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(
            vs_app_nvs_storage_init_impl(&slots_storage_impl, vs_app_nvs_slots_namespace(), VS_SLOTS_STORAGE_MAX_SIZE),
            "Cannot create Slots storage");


    // Soft Security Module
    secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

    // Provision module
    VS_LOG_DEBUG("Initialization provision module");
    ret_code = vs_provision_init(&tl_storage_impl, secmodule_impl, _provision_event);
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