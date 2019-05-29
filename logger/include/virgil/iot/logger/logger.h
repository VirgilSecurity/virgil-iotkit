/*
 *   Copyright (C) 2015-2019 Virgil Security Inc.
 *
 *   Logger library
 *
 */

#ifndef AP_SECURITY_SDK_LOGGER_H
#define AP_SECURITY_SDK_LOGGER_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

//#include <stdlib-config.h>
//#include <logger-config.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

// Default buffer size
#define VS_LOGGER_DEFAULT_BUF_SIZE 256

// Helpers
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

// Logging levels
typedef enum {
    VS_LOGLEV_UNKNOWN = 0xFF, // Errorneous logging level

    VS_LOGLEV_INFO = 0x00,
    VS_LOGLEV_FATAL = 0x10,
    VS_LOGLEV_ALERT = 0x20,
    VS_LOGLEV_CRITICAL = 0x30,
    VS_LOGLEV_ERROR = 0x40,
    VS_LOGLEV_WARNING = 0x50,
    VS_LOGLEV_NOTICE = 0x60,
    VS_LOGLEV_TRACE = 0x70,

    VS_LOGLEV_DEBUG = 0xFE,
} vs_log_level_t;

// Functions

// Initialize logging level
// - log_level : logging logging level to be initialized
// - max_buf_size : maximum buffer size, in bytes. You can use VS_LOGGER_DEFAULT_BUF_SIZE if you are not sure
// Return true if successful

bool
vs_logger_init(vs_log_level_t log_level, size_t max_buf_size);

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

// Log text message
// - level : log level
// - cur_filename : source code file name
// - line_num : source code line number
// - log_format, ... : printf like string
// Return true if there were no errors and string has not been cut
// You can pass cur_filename = NULL and line_num = 0 to make output shorter

bool
vs_logger_message(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *log_format, ...);

// Log message in hex format
// - level : log level
// - cur_filename : source code file name
// - line_num : source code line number
// - prefix : data to print before hex data
// - data_buf : data sequence buffer
// - date_size : data sequence size
// - log_format, ... : printf like string
// Return true if there were no errors

bool
vs_logger_message_hex(vs_log_level_t level,
                      const char *cur_filename,
                      size_t line_num,
                      const char *prefix,
                      const void *data_buf,
                      const size_t data_size);

#endif // AP_SECURITY_SDK_LOGGER_H
