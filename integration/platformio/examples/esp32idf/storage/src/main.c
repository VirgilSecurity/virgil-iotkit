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

// implementation
#include <defaults/netif/netif-udp-broadcast.h>
#include <defaults/storage/storage-esp-impl.h>

// Modules
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/info/info-server.h>

#define CONFIG_EXAMPLE_IPV4
#define UDP_BROADCAST_PORT 4100

extern esp_err_t flash_data_test(void);

// Primitives
//******************************************************************************
vs_status_e vs_snap_info_start_notification(const vs_netif_t *netif);
extern esp_err_t flash_data_init(void);

//******************************************************************************
void app_main()
{
  uint8_t mac[6];
  // Device parameters
  vs_device_manufacture_id_t manufacture_id = {0};
  vs_device_type_t device_type = {0};
  vs_device_serial_t serial = {0};
  // Network
  vs_netif_t *netif_impl = NULL;
  // Storage
  vs_storage_op_ctx_t tl_storage_impl;
  vs_storage_op_ctx_t fw_storage_impl;
  //Services
  const vs_snap_service_t *snap_info_server;

  //wifi_config_t wifi_config;
  vs_logger_init(VS_LOGLEV_DEBUG);

  // Initialize NVS
  VS_LOG_INFO("Initialization NVS flash");
  INIT_STATUS_CHECK(flash_nvs_init(), "NVC Error");

  // Initialize WiFi
  VS_LOG_INFO("Configuring WiFi");
  wifi_config_t wifi_config = {
      .sta = {.ssid = ESP_WIFI_SSID, .password = ESP_WIFI_PASS},
  };
  INIT_STATUS_CHECK(wifi_init_sta(wifi_config), "WIFI Error");
  VS_LOG_INFO("Waiting for AP connection...");
  wifi_ready_wait(portMAX_DELAY);

  // Initialize UDP
  VS_LOG_INFO("Create UDP listener");
  udp_socket_init(4100, 128);

  // Initialization netif
  VS_LOG_DEBUG("Initialization netif");
  netif_impl = vs_hal_netif_udp_bcast();
  VS_IOT_MEMSET(serial, 0x03, sizeof(serial));
  strcpy((char *)manufacture_id, "TEST_ESP32");
  strcpy((char *)device_type, "DVB");
  VS_LOG_DEBUG("Initialization snap");
  STATUS_CHECK(vs_snap_init(netif_impl, manufacture_id, device_type, serial, VS_SNAP_DEV_THING | VS_SNAP_DEV_INITIALIZER), "Unable to initialize SNAP module");

  //  INFO server service
  VS_LOG_DEBUG("Initialization snap info");
  snap_info_server = vs_snap_info_server(NULL);
  VS_LOG_DEBUG("Initialization Register snap info");
  STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO server service");

  // Flash data test write/read files
  //flash_data_test();

  // Prepare flash storage
  STATUS_CHECK(vs_app_prepare_storage("thing"), "Cannot prepare storage");

  // TrustList storage
  STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE), "Cannot create TrustList storage");
  

  while (1)
    ;
terminate:
  VS_LOG_INFO("Application start error");
  while (1)
    ;
}
