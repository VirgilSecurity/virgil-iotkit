#include "init/gpio.h"

void MX_GPIO_Init(void)
{

  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

}
