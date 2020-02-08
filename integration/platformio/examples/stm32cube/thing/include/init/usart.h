#ifndef __usart_H
#define __usart_H
#ifdef __cplusplus
 extern "C" {
#endif

#include "stm32f1xx_hal.h"
#include "init/HAL_Init.h"

extern UART_HandleTypeDef huart1;
extern void _Error_Handler(char *, int);
void MX_USART1_UART_Init(void);

#ifdef __cplusplus
}
#endif
#endif /*__ usart_H */

