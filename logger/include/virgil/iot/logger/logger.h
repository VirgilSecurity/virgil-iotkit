//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#ifndef AP_SECURITY_SDK_LOGGER_H
#define AP_SECURITY_SDK_LOGGER_H

#include <logger-config.h>

// Logging levels
typedef enum {
    VS_LOGLEV_UNKNOWN = 0xFF,   // Errorneous logging level
    VS_LOGLEV_NO_LOGGER = 0xFE, // Logging is disabled

    VS_LOGLEV_INFO = 0x00,
    VS_LOGLEV_FATAL = 0x10,
    VS_LOGLEV_ALERT = 0x20,
    VS_LOGLEV_CRITICAL = 0x30,
    VS_LOGLEV_ERROR = 0x40,
    VS_LOGLEV_WARNING = 0x50,
    VS_LOGLEV_NOTICE = 0x60,
    VS_LOGLEV_TRACE = 0x70,

    VS_LOGLEV_DEBUG = 0xFD,
} vs_log_level_t;

#if VS_IOT_LOGGER_USE_LIBRARY == 1

#include <stdbool.h>
#include <stdint.h>
#include <stdlib-config.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

// Helpers
#define VS_LOG_GET_LOGLEVEL(LOGLEV_VARIABLE) (LOGLEV_VARIABLE) = vs_logger_get_loglev()
#define VS_LOG_IS_LOGLEVEL(LOGLEV_VALUE) vs_logger_is_loglev(LOGLEV_VALUE)
#define VS_LOG_SET_LOGLEVEL(LOGLEV_VALUE) vs_logger_set_loglev(LOGLEV_VALUE)

#define VS_LOG(LGLVL, FRMT, ...) vs_logger_message((LGLVL), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_HEX(LGLVL, FRMT, ...) vs_logger_message_hex((LGLVL), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)

#define VS_LOG_INFO(FRMT, ...) vs_logger_message(VS_LOGLEV_INFO, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_FATAL(FRMT, ...) vs_logger_message(VS_LOGLEV_FATAL, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_ALERT(FRMT, ...) vs_logger_message(VS_LOGLEV_ALERT, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_CRITICAL(FRMT, ...) vs_logger_message(VS_LOGLEV_CRITICAL, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_ERROR(FRMT, ...) vs_logger_message(VS_LOGLEV_ERROR, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_WARNING(FRMT, ...) vs_logger_message(VS_LOGLEV_WARNING, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_NOTICE(FRMT, ...) vs_logger_message(VS_LOGLEV_NOTICE, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_TRACE(FRMT, ...) vs_logger_message(VS_LOGLEV_TRACE, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_DEBUG(FRMT, ...) vs_logger_message(VS_LOGLEV_DEBUG, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)

// Functions

// Last result
// Return true if there were no errors during last call and log level was appropriate.

bool
vs_logger_last_result(void);


// Log text message
// - level : log level
// - cur_filename : source code file name
// - line_num : source code line number
// - log_format, ... : printf like string
// Return true if there were no errors and string has not been cut
// You can pass cur_filename = NULL and line_num = 0 to make output shorter

void
vs_logger_message(vs_log_level_t level, const char *cur_filename, uint32_t line_num, const char *log_format, ...);

// Initialize logging level
// - log_level : logging logging level to be initialized
// - max_buf_size : maximum buffer size, in bytes. You can use VS_LOGGER_DEFAULT_BUF_SIZE if you are not sure
// Return true if successful

void
vs_logger_init(vs_log_level_t log_level);

// Set current logging level
// - new_level : new logging level to be initialized
// Return previous logging level

vs_log_level_t
vs_logger_set_loglev(vs_log_level_t new_level);

// Get current logging level
// Return VS_LOGLEV_UNKNOWN if any error

vs_log_level_t
vs_logger_get_loglev(void);

// Check that specified logging level is enabled
// Return true if specified logging level is enabled and there are now any error

bool
vs_logger_is_loglev(vs_log_level_t level);

// Log message in hex format
// - level : log level
// - cur_filename : source code file name
// - line_num : source code line number
// - prefix : data to print before hex data
// - data_buf : data sequence buffer
// - date_size : data sequence size
// - log_format, ... : printf like string
// Return true if there were no errors

void
vs_logger_message_hex(vs_log_level_t level,
                      const char *cur_filename,
                      uint32_t line_num,
                      const char *prefix,
                      const void *data_buf,
                      const size_t data_size);

#elif VS_IOT_LOGGER_USE_LIBRARY != 1 && defined(VS_IOT_LOGGER_FUNCTION)

#define VS_LOG_GET_LOGLEVEL(LOGLEV_VARIABLE)    (void) LOGLEV_VARIABLE;
#define VS_LOG_IS_LOGLEVEL(LOGLEV_VALUE)        (void) LOGLEV_VALUE;
#define VS_LOG_SET_LOGLEVEL(LOGLEV_VALUE)       (void) LOGLEV_VALUE;

#define VS_LOG(LGLVL, FRMT, ...)        do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_HEX(LGLVL, FRMT, ...)    do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_INFO(FRMT, ...)          do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_FATAL(FRMT, ...)         do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_ALERT(FRMT, ...)         do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_CRITICAL(FRMT, ...)      do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_ERROR(FRMT, ...)         do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_WARNING(FRMT, ...)       do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_NOTICE(FRMT, ...)        do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_TRACE(FRMT, ...)         do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)
#define VS_LOG_DEBUG(FRMT, ...)         do{ VS_IOT_LOGGER_FUNCTION(FRMT, ## __VA_ARGS__); VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL); } while(0)

#define vs_logger_last_result()         true
#define vs_logger_message(...)
#define vs_logger_init(log_level)       (void) log_level;
#define vs_logger_set_loglev(...)       VS_LOGLEV_NO_LOGGER
#define vs_logger_get_loglev(...)       VS_LOGLEV_NO_LOGGER
#define vs_logger_is_loglev(level)      ((level) == VS_LOGLEV_NO_LOGGER)
#define vs_logger_message_hex(...);

#else

#define VS_LOG_GET_LOGLEVEL(LOGLEV_VARIABLE)    (void) LOGLEV_VARIABLE;
#define VS_LOG_IS_LOGLEVEL(LOGLEV_VALUE)        (void) LOGLEV_VALUE;
#define VS_LOG_SET_LOGLEVEL(LOGLEV_VALUE)       (void) LOGLEV_VALUE;

#define vs_logger_last_result()         true
#define vs_logger_message(...)
#define vs_logger_init(log_level)       (void) log_level;
#define vs_logger_set_loglev(...)       VS_LOGLEV_NO_LOGGER
#define vs_logger_get_loglev(...)       VS_LOGLEV_NO_LOGGER
#define vs_logger_is_loglev(level)      ((level) == VS_LOGLEV_NO_LOGGER)
#define vs_logger_message_hex(...);

#define VS_LOG(LGLVL, FRMT, ...)
#define VS_LOG_HEX(LGLVL, FRMT, ...)
#define VS_LOG_INFO(FRMT, ...)
#define VS_LOG_FATAL(FRMT, ...)
#define VS_LOG_ALERT(FRMT, ...)
#define VS_LOG_CRITICAL(FRMT, ...)
#define VS_LOG_ERROR(FRMT, ...)
#define VS_LOG_WARNING(FRMT, ...)
#define VS_LOG_NOTICE(FRMT, ...)
#define VS_LOG_TRACE(FRMT, ...)
#define VS_LOG_DEBUG(FRMT, ...)



#endif // VS_IOT_LOGGER_USE_LIBRARY == 1

#endif // AP_SECURITY_SDK_LOGGER_H
