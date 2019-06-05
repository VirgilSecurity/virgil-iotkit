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

#include <stdbool.h>
#include <stdlib-config.h>
#include <logger-config.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

// Default buffer size
#define VS_LOGGER_DEFAULT_BUF_SIZE 256

// Helpers
#define VS_LOG(LGLVL, FRMT, ...) vs_logger_message((LGLVL), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_HEX(LGLVL, FRMT, ...) vs_logger_message((LGLVL), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)

#define VS_LOG_INFO(FRMT, ...) vs_logger_message(VS_LOGLEV_INFO, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_FATAL(FRMT, ...) vs_logger_message(VS_LOGLEV_FATAL, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_ALERT(FRMT, ...) vs_logger_message(VS_LOGLEV_ALERT, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_CRITICAL(FRMT, ...) vs_logger_message(VS_LOGLEV_CRITICAL, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_ERROR(FRMT, ...) vs_logger_message(VS_LOGLEV_ERROR, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_WARNING(FRMT, ...) vs_logger_message(VS_LOGLEV_WARNING, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_NOTICE(FRMT, ...) vs_logger_message(VS_LOGLEV_NOTICE, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_TRACE(FRMT, ...) vs_logger_message(VS_LOGLEV_TRACE, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
#define VS_LOG_DEBUG(FRMT, ...) vs_logger_message(VS_LOGLEV_DEBUG, __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)

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

// Functions

// Log text message
// - level : log level
// - cur_filename : source code file name
// - line_num : source code line number
// - log_format, ... : printf like string
// Return true if there were no errors and string has not been cut
// You can pass cur_filename = NULL and line_num = 0 to make output shorter

#if !defined(VS_IOT_LOGGER_ENABLE)
static inline bool
vs_logger_message(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *log_format, ...) {
    (void)level;
    (void)cur_filename;
    (void)line_num;
    (void)log_format;
    return true;
}
#elif defined(VS_IOT_LOGGER_ENABLE) && defined(VS_IOT_LOGGER_ONE_FUNCTION)
#define vs_logger_message(level, cur_filename, line_num, format, ...)                                                  \
    VS_IOT_LOGGER_ONE_FUNCTION((level), (cur_filename), (line_num), (format), ##__VA_ARGS__)
#else
bool
vs_logger_message(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *log_format, ...);
#endif // VS_IOT_LOGGER_ONE_FUNCTION

// Initialize logging level
// - log_level : logging logging level to be initialized
// - max_buf_size : maximum buffer size, in bytes. You can use VS_LOGGER_DEFAULT_BUF_SIZE if you are not sure
// Return true if successful

#if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)
static inline bool
vs_logger_init(vs_log_level_t log_level, size_t max_buf_size) {
    (void)log_level;
    (void)max_buf_size;
    return true;
}
#else
bool
vs_logger_init(vs_log_level_t log_level, size_t max_buf_size);
#endif // #if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)

// Set current logging level
// - new_level : new logging level to be initialized
// Return previous logging level

#if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)
static inline vs_log_level_t
vs_logger_set_loglev(vs_log_level_t new_level) {
    (void)new_level;
    return VS_LOGLEV_NO_LOGGER;
}
#else
vs_log_level_t
vs_logger_set_loglev(vs_log_level_t new_level);
#endif // #if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)

// Get current logging level
// Return VS_LOGLEV_UNKNOWN if any error

#if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)
static inline vs_log_level_t
vs_logger_get_loglev(void) {
    return VS_LOGLEV_NO_LOGGER;
}
#else
vs_log_level_t
vs_logger_get_loglev(void);
#endif // #if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)

// Check that specified logging level is enabled
// Return true if specified logging level is enabled and there are now any error

#if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)
static inline bool
vs_logger_is_loglev(vs_log_level_t level) {
    return level == VS_LOGLEV_NO_LOGGER;
}
#else
bool
vs_logger_is_loglev(vs_log_level_t level);
#endif // #if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)

// Log message in hex format
// - level : log level
// - cur_filename : source code file name
// - line_num : source code line number
// - prefix : data to print before hex data
// - data_buf : data sequence buffer
// - date_size : data sequence size
// - log_format, ... : printf like string
// Return true if there were no errors

#if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)
static inline bool
vs_logger_message_hex(vs_log_level_t level,
                      const char *cur_filename,
                      size_t line_num,
                      const char *prefix,
                      const void *data_buf,
                      const size_t data_size) {
    (void)level;
    (void)cur_filename;
    (void)line_num;
    (void)prefix;
    (void)data_buf;
    (void)data_size;

    return true;
}
#else
bool
vs_logger_message_hex(vs_log_level_t level,
                      const char *cur_filename,
                      size_t line_num,
                      const char *prefix,
                      const void *data_buf,
                      const size_t data_size);
#endif // #if !defined(VS_IOT_LOGGER_ENABLE) || defined(VS_IOT_LOGGER_ONE_FUNCTION)

#endif // AP_SECURITY_SDK_LOGGER_H
