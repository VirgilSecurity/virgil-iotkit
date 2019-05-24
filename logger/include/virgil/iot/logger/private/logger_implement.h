/*
 *   Copyright (C) 2015-2019 Virgil Security Inc.
 *
 *   Logger library HAL interface
 *
 */

#ifndef AP_SECURITY_SDK_LOGGER_HAL_H
#define AP_SECURITY_SDK_LOGGER_HAL_H

/*
 * HAL interface
 */

// Output ASCIIZ string
// buf - null terminated ASCII string to be output
// return true if successful
bool
vs_logger_implement(const char *buf);

#endif // AP_SECURITY_SDK_LOGGER_HAL_H
