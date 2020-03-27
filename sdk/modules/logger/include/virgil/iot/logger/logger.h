//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

/*! \file logger.h
 * \brief Logger implementation
 *
 * Logger allows to log messages to output stream that can be file or screen. User can enable different logging levels
 * like debug, info, error etc. (see #vs_log_level_t). In future versions sending report through network is planned
 *
 * \section logger_usage Logger Usage
 *
 * See the following snippet for the logger usage examples :
 *
 * \code

vs_logger_init( VS_LOGLEV_WARNING );    // Warning level and upper ones are enabled
VS_LOG_FATAL("Serious error");          // Outputs fatal error if enabled

// Hex data output
const uint8_t raw_data[] = "Some raw data";
VS_LOG_HEX(VS_LOGLEV_DEBUG, "Raw data : ", raw_data, sizeof(raw_data));

// Some operation with false positive errors, need to temporary disable error messages
vs_log_level_t prev_log_level;
prev_log_level = vs_logger_set_loglev(VS_LOGLEV_FATAL);  // Enable fatal level and upper ones
// ...
vs_logger_set_loglev(prev_log_level);       // Restore previous logger level

 * \endcode
 *
 * \warning If #VS_IOT_LOGGER_USE_LIBRARY == 1, #vs_logger_output_hal implementation is required. See \ref
logger_hal_implementation
 * for details.
 *
 */

#ifndef AP_SECURITY_SDK_LOGGER_H
#define AP_SECURITY_SDK_LOGGER_H

#include <logger-config.h>
#include <stdarg.h>
#include <string.h>

#if VS_IOT_LOGGER_USE_LIBRARY
#include <stdbool.h>
#include <stdint.h>
#include <stdlib-config.h>
#endif // VS_IOT_LOGGER_USE_LIBRARY


#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Logging level
 */
typedef enum {
    VS_LOGLEV_UNKNOWN = 0xFF,   /**< Invalid logging level */
    VS_LOGLEV_NO_LOGGER = 0xFE, /**< Logging is disabled */

    VS_LOGLEV_INFO = 0x00,     /**< Information messages */
    VS_LOGLEV_FATAL = 0x10,    /**< Fatal messages */
    VS_LOGLEV_ALERT = 0x20,    /**< Alert messages */
    VS_LOGLEV_CRITICAL = 0x30, /**< Critical messages */
    VS_LOGLEV_ERROR = 0x40,    /**< Error messages */
    VS_LOGLEV_WARNING = 0x50,  /**< Warning messages */
    VS_LOGLEV_NOTICE = 0x60,   /**< Notifications */
    VS_LOGLEV_TRACE = 0x70,    /**< Trace messages */

    VS_LOGLEV_DEBUG = 0xFD, /**< Debug messages */
} vs_log_level_t;

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/** Get current logging level to \a LOGLEV_VARIABLE */
#define VS_LOG_GET_LOGLEVEL(LOGLEV_VARIABLE) (LOGLEV_VARIABLE) = vs_logger_get_loglev()
/** Is \a LOGLEV_VALUE logging level is enabled */
#define VS_LOG_IS_LOGLEVEL(LOGLEV_VALUE) vs_logger_is_loglev(LOGLEV_VALUE)
/** Set \a LOGLEV_VALUE as current logging level */
#define VS_LOG_SET_LOGLEVEL(LOGLEV_VALUE) vs_logger_set_loglev(LOGLEV_VALUE)


#if VS_IOT_LOGGER_USE_LIBRARY

/** Log message
 *
 * Sends \a FRMT message by calling #vs_logger_message function.
 *
 * \param[in] LGLVL Logging level.
 * \param[in] FRMT printf-like format string and arguments.
 */
#define VS_LOG(LGLVL, FRMT, ...) vs_logger_message((LGLVL), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)

/** Log HEX buffer
 *
 * Sends \a BUF as hex string by calling #vs_logger_message function.
 *
 * \param[in] LGLVL Logging level
 * \param[in] PREFIX Prefix for output. Must not be NULL.
 * \param[in] BUF Buffer to be output as HEX. Must not be NULL.
 * \param[in] SIZE Size of the array to be output as HEX. Must not be zero.
 */
#define VS_LOG_HEX(LGLVL, PREFIX, BUF, SIZE)                                                                           \
    vs_logger_message_hex((LGLVL), __FILENAME__, __LINE__, (PREFIX), (BUF), (SIZE))

/** Set current thread description
 *
 * \note This function does nothing if #VS_IOT_LOGGER_OUTPUT_THREAD_ID is not set to 1
 *
 * \param description Human readable thread description.
 * \warning description must be static string pointer valid during program functioning
 *
 * \return false if no space is available to store thread description
 */
bool
vs_log_thread_descriptor(const char *description);

#ifdef __cplusplus
#define VS_LOG_MAKE_LEVEL(LEVEL) VirgilIoTKit::LEVEL
#else
#define VS_LOG_MAKE_LEVEL(LEVEL) LEVEL
#endif

/** Log message with #VS_LOGLEV_INFO level */
#define VS_LOG_INFO(FRMT, ...)                                                                                         \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_INFO), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
/** Log message with #VS_LOGLEV_FATAL level */
#define VS_LOG_FATAL(FRMT, ...)                                                                                        \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_FATAL), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
/** Log message with #VS_LOGLEV_ALERT level */
#define VS_LOG_ALERT(FRMT, ...)                                                                                        \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_ALERT), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
/** Log message with #VS_LOGLEV_CRITICAL level */
#define VS_LOG_CRITICAL(FRMT, ...)                                                                                     \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_CRITICAL), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
/** Log message with #VS_LOGLEV_ERROR level */
#define VS_LOG_ERROR(FRMT, ...)                                                                                        \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_ERROR), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
/** Log message with #VS_LOGLEV_WARNING level */
#define VS_LOG_WARNING(FRMT, ...)                                                                                      \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_WARNING), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
/** Log message with #VS_LOGLEV_NOTICE level */
#define VS_LOG_NOTICE(FRMT, ...)                                                                                       \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_NOTICE), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
/** Log message with #VS_LOGLEV_TRACE level */
#define VS_LOG_TRACE(FRMT, ...)                                                                                        \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_TRACE), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)
/** Log message with #VS_LOGLEV_DEBUG level */
#define VS_LOG_DEBUG(FRMT, ...)                                                                                        \
    vs_logger_message(VS_LOG_MAKE_LEVEL(VS_LOGLEV_DEBUG), __FILENAME__, __LINE__, (FRMT), ##__VA_ARGS__)

// Functions

/** Last result
 *
 * Return true if there were no errors during last call and log level was appropriate.
 *
 * \return true if last output was successful and false otherwise
 */

bool
vs_logger_last_result(void);

/** Log text message
 *
 * Sends \a FRMT output message with current time if #VS_IOT_LOGGER_OUTPUT_TIME is enabled, filename, line number
 * and user message. Buffer size is limited by #VS_IOT_LOGGER_MAX_BUFFER_SIZE define.
 *
 * \param[in] level Message log level
 * \param[in] cur_filename Source code file name. If NULL, there will be no filename information.
 * \param[in] line_num Source code line number. If zero, there will be no line number.
 * \param[in] log_format printf like string
 *
 * \return true if there were no errors and string has not been cut
 */
void
vs_logger_message(vs_log_level_t level, const char *cur_filename, uint32_t line_num, const char *log_format, ...);

/** Initialize logging level
 *
 * \a log_level is initialized and default title for thread is provided. You can change this name by
 * #vs_log_thread_descriptor call
 *
 * \param[int] log_level Message log level
 */
void
vs_logger_init(vs_log_level_t log_level);

/** Set current logging level
 *
 * \param[in] new_level New logging level to be initialized
 *
 * \return vs_log_level_t previous log level
 */

vs_log_level_t
vs_logger_set_loglev(vs_log_level_t new_level);

/** Get current logging level
 *
 * \return #VS_LOGLEV_UNKNOWN in cse of error
 */

vs_log_level_t
vs_logger_get_loglev(void);

/** Check that specified logging level is enabled
 *
 * \param[in] level Logging level to be tested
 *
 * \return true if specified logging level is enabled and there are now any error
 */

bool
vs_logger_is_loglev(vs_log_level_t level);

/** Log HEX buffer
 *
 * Sends \a BUF as hex string by calling #vs_logger_message function.
 *
 * \param[in] level Logging level
 * \param[in] cur_filename Source code file name. If NULL, there will be no filename information.
 * \param[in] line_num Source code line number. If zero, there will be no line number.
 * \param[in] prefix Prefix for output. Must not be NULL.
 * \param[in] data_buf Buffer to be output as HEX. Must not be NULL.
 * \param[in] SIZE Size of the array to be output as HEX. Must not be zero.
 */

void
vs_logger_message_hex(vs_log_level_t level,
                      const char *cur_filename,
                      uint32_t line_num,
                      const char *prefix,
                      const void *data_buf,
                      const uint16_t data_size);

#elif VS_IOT_LOGGER_USE_LIBRARY != 1 && defined(VS_IOT_LOGGER_FUNCTION)

#define vs_logger_last_result() true
#define vs_logger_init(log_level) (void)log_level;
#define vs_logger_set_loglev(log_level) (void)log_level;
#define vs_logger_get_loglev() VS_LOGLEV_NO_LOGGER
#define vs_logger_is_loglev(level) ((level) == VS_LOGLEV_NO_LOGGER)

#define vs_logger_message_hex(level, cur_filename, line_num, prefix, data_buf, data_size)                              \
    do {                                                                                                               \
        (void)level;                                                                                                   \
        (void)cur_filename;                                                                                            \
        (void)line_num;                                                                                                \
        (void)prefix;                                                                                                  \
        (void)data_buf;                                                                                                \
        (void)data_size;                                                                                               \
    } while (0)

#define vs_logger_message(level, cur_filename, line_num, log_format, ...)                                              \
    do {                                                                                                               \
        (void)level;                                                                                                   \
        (void)cur_filename;                                                                                            \
        (void)line_num;                                                                                                \
        VS_IOT_LOGGER_FUNCTION((log_format), ##__VA_ARGS__);                                                           \
        VS_IOT_LOGGER_FUNCTION(VS_IOT_LOGGER_EOL);                                                                     \
    } while (0)

#else // VS_IOT_LOGGER_USE_LIBRARY != 1 && !defined(VS_IOT_LOGGER_FUNCTION)

#include "macro_va_args.h"

#define vs_logger_last_result() true
#define vs_logger_init(log_level) (void)log_level;
#define vs_logger_set_loglev(log_level) (void)log_level;
#define vs_logger_get_loglev() VS_LOGLEV_NO_LOGGER
#define vs_logger_is_loglev(level) ((level) == VS_LOGLEV_NO_LOGGER)
#define vs_log_thread_descriptor() (true)

#define VS_IOT_LOGGER_VOID(a) (void)a;

#define VS_LOG(LGLVL, FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_HEX(LGLVL, PREFIX, BUF, SIZE) VS_IOT_MAP(VS_IOT_LOGGER_VOID, PREFIX, BUF, SIZE)
#define VS_LOG_INFO(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_FATAL(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_ALERT(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_CRITICAL(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_ERROR(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_WARNING(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_NOTICE(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_TRACE(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)
#define VS_LOG_DEBUG(FRMT, ...) VS_IOT_MAP(VS_IOT_LOGGER_VOID, FRMT, ##__VA_ARGS__)

#endif // VS_IOT_LOGGER_USE_LIBRARY

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // AP_SECURITY_SDK_LOGGER_H
