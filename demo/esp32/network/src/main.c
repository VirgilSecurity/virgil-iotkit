<<<<<<< HEAD
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
#include <defaults/vs-soft-secmodule/vs-soft-secmodule.h>

// Modules
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/info/info-server.h>

#define CONFIG_EXAMPLE_IPV4
#define UDP_BROADCAST_PORT 4100

// Primitives 
//******************************************************************************
vs_status_e vs_snap_info_start_notification(const vs_netif_t *netif);

//******************************************************************************
void app_main()
{
  // Device parameters
  vs_device_manufacture_id_t manufacture_id = "TEST_ESP32";
  vs_device_type_t device_type = "DVB";
  vs_device_serial_t serial;
  vs_secmodule_impl_t *secmodule_impl;

  // Network
  wifi_config_t wifi_config = {
      .sta = {.ssid = ESP_WIFI_SSID, .password = ESP_WIFI_PASS},
  };
  vs_netif_t *netif_impl = NULL;

  // Storage 
  vs_storage_op_ctx_t  slots_storage_impl;
  vs_storage_op_ctx_t tl_storage_impl;
  vs_storage_op_ctx_t fw_storage_impl;

  //Services
  const vs_snap_service_t *snap_info_server;

  vs_logger_init(VS_LOGLEV_DEBUG);

  // Initialize NVS
  VS_LOG_INFO("Initialization NVS flash");
  INIT_STATUS_CHECK(flash_nvs_init(), "NVC Error");

  // Initialize WiFi
  VS_LOG_INFO("Configuring WiFi");
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

  // Soft Security Module
  secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

  // Provision module
  STATUS_CHECK(vs_provision_init(&tl_storage_impl, secmodule_impl), "Cannot initialize Provision module");

  VS_LOG_DEBUG("Initialization snap");
  STATUS_CHECK(vs_snap_init(netif_impl, manufacture_id, device_type, serial, VS_SNAP_DEV_THING | VS_SNAP_DEV_INITIALIZER), "Unable to initialize SNAP module");

  //  INFO server service
  VS_LOG_DEBUG("Initialization snap info");
  snap_info_server = vs_snap_info_server(NULL);
  VS_LOG_DEBUG("Initialization Register snap info");
  STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO server service");

  vTaskDelay(1000 / portTICK_PERIOD_MS);

  while (1);
terminate:
  VS_LOG_INFO("Application start error");
  while (1);
}
=======
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

#include <init/flash_nvs.h>
#include <init/wifi_network.h>
#include <init/udp_socket.h>
#include <virgil/iot/logger/logger.h>

// implementation
#include <defaults/netif/netif-udp-broadcast.h>
#include <defaults/vs-soft-secmodule/vs-soft-secmodule.h>

// Modules
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/info/info-server.h>

#define CONFIG_EXAMPLE_IPV4
#define UDP_BROADCAST_PORT 4100

// Primitives 
//******************************************************************************
vs_status_e vs_snap_info_start_notification(const vs_netif_t *netif);

//******************************************************************************
void app_main()
{
  // Device parameters
  vs_device_manufacture_id_t manufacture_id = "TEST_ESP32";
  vs_device_type_t device_type = "DVB";
  vs_device_serial_t serial;
  vs_secmodule_impl_t *secmodule_impl;

  // Network
  wifi_config_t wifi_config = {
      .sta = {.ssid = ESP_WIFI_SSID, .password = ESP_WIFI_PASS},
  };
  vs_netif_t *netif_impl = NULL;

  // Storage 
  vs_storage_op_ctx_t  slots_storage_impl;
  vs_storage_op_ctx_t tl_storage_impl;
  vs_storage_op_ctx_t fw_storage_impl;

  //Services
  const vs_snap_service_t *snap_info_server;

  vs_logger_init(VS_LOGLEV_DEBUG);

  // Initialize NVS
  VS_LOG_INFO("Initialization NVS flash");
  INIT_STATUS_CHECK(flash_nvs_init(), "NVC Error");

  // Initialize WiFi
  VS_LOG_INFO("Configuring WiFi");
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

  // Soft Security Module
  secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

  // Provision module
  STATUS_CHECK(vs_provision_init(&tl_storage_impl, secmodule_impl), "Cannot initialize Provision module");

  VS_LOG_DEBUG("Initialization snap");
  STATUS_CHECK(vs_snap_init(netif_impl, manufacture_id, device_type, serial, VS_SNAP_DEV_THING | VS_SNAP_DEV_INITIALIZER), "Unable to initialize SNAP module");

  //  INFO server service
  VS_LOG_DEBUG("Initialization snap info");
  snap_info_server = vs_snap_info_server(NULL);
  VS_LOG_DEBUG("Initialization Register snap info");
  STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO server service");

  vTaskDelay(1000 / portTICK_PERIOD_MS);

  while (1);
terminate:
  VS_LOG_INFO("Application start error");
  while (1);
}
>>>>>>> 58b9413520376a11b957bee685bdf98af5324de5
