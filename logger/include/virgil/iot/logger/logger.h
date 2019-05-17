//
// Created by Oleksandr Nemchenko on 2019-05-17.
//

#ifndef AP_SECURITY_SDK_LOGGER_H
#define AP_SECURITY_SDK_LOGGER_H

#include <stdbool.h>

// HAL interface
bool vs_logger_print_hal(const char *buf); // Output ASCIIZ string

void vs_logger_start(const char *msg);

#endif // AP_SECURITY_SDK_LOGGER_H
