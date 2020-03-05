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
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/tests/helpers.h>
// implementation
#include <defaults/netif/netif-udp-broadcast.h>
#include <defaults/storage/storage-esp-impl.h>

// Modules
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/info/info-server.h>

#define CONFIG_EXAMPLE_IPV4
#define UDP_BROADCAST_PORT 4100

extern esp_err_t
flash_data_test(void);

#define TEST_FILENAME_DATA "testfile.txt"

static const char *_test_data = "Little string for test";

static void
_test_exec_task(void *pvParameters);

//******************************************************************************
void
app_main(void) {
    vs_logger_init(VS_LOGLEV_DEBUG);
    xTaskCreate(_test_exec_task, "_initializer_task", 8 * 4096, NULL, 5, NULL);
    while (1) {
        vTaskDelay(10);
    }
}

//******************************************************************************
static vs_status_e
_storage_test(vs_storage_op_ctx_t *storage_ctx, uint8_t *test_data, size_t len) {

    uint16_t failed_test_result = 0;
    vs_storage_file_t f = NULL;
    vs_storage_element_id_t id;
    uint8_t buf[len];
    ssize_t size;

    VS_IOT_STRCPY((char *)id, TEST_FILENAME_DATA);

    TEST_CASE("Open file for writing", f = storage_ctx->impl_func.open(storage_ctx->impl_data, id));

    TEST_CASE("Write file", VS_CODE_OK == storage_ctx->impl_func.save(storage_ctx->impl_data, f, 0, test_data, len));

    TEST_CASE("Sync file", VS_CODE_OK == storage_ctx->impl_func.sync(storage_ctx->impl_data, f));

    TEST_CASE("Close file", VS_CODE_OK == storage_ctx->impl_func.close(storage_ctx->impl_data, f));
    f = NULL;

    TEST_CASE("Open file for reading", f = storage_ctx->impl_func.open(storage_ctx->impl_data, id));

    TEST_CASE("Read file", VS_CODE_OK == storage_ctx->impl_func.load(storage_ctx->impl_data, f, 0, buf, sizeof(buf)));

    START_ELEMENT("Cmp data");
    MEMCMP_CHECK_RET(buf, test_data, sizeof(buf), ++failed_test_result);
    RESULT_OK;

    START_ELEMENT("[TEST] Size of file");
    size = storage_ctx->impl_func.size(storage_ctx->impl_data, id);
    CHECK((size > 0 && size == sizeof(buf)), "[TEST-FAILURE]");
    VS_LOG_DEBUG("Read size = %d", size);
    RESULT_OK;

terminate:
    if (f) {
        TEST_CASE("Close file", VS_CODE_OK == storage_ctx->impl_func.close(storage_ctx->impl_data, f));
    }

    TEST_CASE("Delete file", VS_CODE_OK == storage_ctx->impl_func.del(storage_ctx->impl_data, id));

    return failed_test_result;
}

//******************************************************************************
static uint16_t
_partition_test(void) {
    uint16_t failed_test_result = 0;

    START_TEST("Mount partitions");

    TEST_CASE("Mount ESP_HSM_PARTITION_NAME", VS_CODE_OK == vs_app_init_partition(ESP_HSM_PARTITION_NAME));

    TEST_CASE("Try to mount ESP_HSM_PARTITION_NAME again", vs_app_init_partition(ESP_HSM_PARTITION_NAME) != VS_CODE_OK);

    TEST_CASE("Unmount ESP_HSM_PARTITION_NAME again", VS_CODE_OK == vs_app_deinit_partition(ESP_HSM_PARTITION_NAME));

    TEST_CASE("Mount ESP_HSM_PARTITION_NAME", VS_CODE_OK == vs_app_init_partition(ESP_HSM_PARTITION_NAME));

    TEST_CASE("Mount ESP_FW_STORAGE_PARTITION_NAME",
              VS_CODE_OK == vs_app_init_partition(ESP_FW_STORAGE_PARTITION_NAME));

terminate:
    return failed_test_result;
}

//******************************************************************************
static void
_test_exec_task(void *pvParameters) {
    uint16_t failed_test_result = -1;
    char *_big_test_data = NULL;
    size_t big_test_size = (3 * 256 + 128 - 1);

    _big_test_data = VS_IOT_MALLOC(big_test_size);
    if (!_big_test_data) {
        VS_LOG_ERROR("Allocation memory for _big_test_data error");
        goto terminate;
    }
    for (uint32_t i = 0; i < big_test_size; i++) {
        _big_test_data[i] = (uint8_t)i;
    }

    // Storage
    vs_storage_op_ctx_t slots_storage_impl;
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t secbox_storage_impl;
    vs_storage_op_ctx_t fw_storage_impl;

    vs_logger_init(VS_LOGLEV_DEBUG);

    // Initialize NVS
    VS_LOG_INFO("Initialization NVS flash");
    INIT_STATUS_CHECK(flash_nvs_init(), "NVC Error");

    // Flash data test write/read files
    // flash_data_test();

    // Test partition
    CHECK(0 == (failed_test_result = _partition_test()), "Partition tests fail");

    // Slots storage
    STATUS_CHECK(vs_app_storage_init_impl(&slots_storage_impl, vs_app_slots_dir(), 512), "Cannot create slots storage");
    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), 512),
                 "Cannot create TrustList storage");
    // Firmware storage
    STATUS_CHECK(vs_app_storage_init_impl(&fw_storage_impl, vs_app_firmware_dir(), 512),
                 "Cannot create Firmware storage");
    // Secbox storage
    STATUS_CHECK(vs_app_storage_init_impl(&secbox_storage_impl, vs_app_secbox_dir(), 512),
                 "Cannot create Secbox storage");

    START_TEST("Slots storage");
    failed_test_result += _storage_test(&slots_storage_impl, (uint8_t *)_test_data, strlen(_test_data));
    CHECK(0 == failed_test_result, "Slot storage test fail");

    START_TEST("TL storage");
    failed_test_result += _storage_test(&tl_storage_impl, (uint8_t *)_test_data, strlen(_test_data));
    CHECK(0 == failed_test_result, "TL storage test fail");

    START_TEST("FW images storage");
    failed_test_result +=
            _storage_test(&fw_storage_impl, (uint8_t *)_test_data, strlen(_test_data));
    CHECK(0 == failed_test_result, "FW storage test fail");

    START_TEST("Secbox storage");
    failed_test_result += _storage_test(&secbox_storage_impl, (uint8_t *)_test_data, strlen(_test_data));
    CHECK(0 == failed_test_result, "Secbox storage test fail");

    START_TEST("Big data operations");
    failed_test_result += _storage_test(&slots_storage_impl, (uint8_t *)_big_test_data, big_test_size);
    CHECK(0 == failed_test_result, "Slot storage test fail");


terminate:
    VS_IOT_FREE(_big_test_data);

    VS_LOG_INFO("Test fails = %d", failed_test_result);

    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
