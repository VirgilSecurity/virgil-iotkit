
#include <virgil/iot/logger/logger.h>
#include <stm32f1xx_hal.h>
#include <init/HAL_Init.h>
#include <init/usart.h>

/******************************************************************************/
int main()
{
// Initialization STM32 HAL 
   HW_Init();

// Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);
    VS_LOG_INFO("Test logging.");

    while(1) {
      HAL_Delay(1000);
      VS_LOG_INFO("Loop logging print");
    }

}
