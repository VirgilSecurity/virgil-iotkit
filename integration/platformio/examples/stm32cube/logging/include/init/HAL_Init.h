#ifndef __HAL_INIT_H__
#define __HAL_INIT_H__

#ifdef __cplusplus
 extern "C" {
#endif

void _Error_Handler(char *, int);

int HW_Init(void);

#define Error_Handler() _Error_Handler(__FILE__, __LINE__)
#ifdef __cplusplus
}
#endif

#endif /* __HAL_INIT_H__ */
