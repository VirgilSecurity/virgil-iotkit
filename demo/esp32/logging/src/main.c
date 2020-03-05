#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include <driver/uart.h>
#include "sdkconfig.h"
#include <virgil-iotkit.h>


/******************************************************************************/
void app_main(void)
{
  vs_logger_init(VS_LOGLEV_DEBUG);
  VS_LOG_INFO("Starting test logging");
  while(1) {
    VS_LOG_INFO("Loop print logging");
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}

