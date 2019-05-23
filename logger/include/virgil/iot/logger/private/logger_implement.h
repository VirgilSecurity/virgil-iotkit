//
// Created by Oleksandr Nemchenko on 2019-05-17.
//

#ifndef AP_SECURITY_SDK_LOGGER_HAL_H
#define AP_SECURITY_SDK_LOGGER_HAL_H

/*
 * HAL interface
 */

// Output ASCIIZ string
bool vs_logger_implement(const char *buf);

// Output current time
bool vs_logger_output_time(void);

#endif // AP_SECURITY_SDK_LOGGER_HAL_H
