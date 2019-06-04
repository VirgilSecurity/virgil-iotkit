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

#include <stdlib-config.h>
#include <logger-config.h>

#include <stdbool.h>

#include <logger.h>



#ifdef VS_IOT_LOGGER_ENABLE



#include <stdarg.h>

#include <logger_hal.h>

static vs_log_level_t _log_level = VS_LOGLEV_UNKNOWN;
static size_t _max_buf_size = 0;

/******************************************************************************/
bool
vs_logger_init(vs_log_level_t log_level, size_t max_buf_size) {
    vs_logger_set_loglev(log_level);

    _max_buf_size = max_buf_size;
    if (!max_buf_size) {
        return false;
    }

    return true;
}

/******************************************************************************/
vs_log_level_t
vs_logger_set_loglev(vs_log_level_t new_level) {
    vs_log_level_t prev_level = _log_level;

    _log_level = new_level;

    return prev_level;
}

/******************************************************************************/
vs_log_level_t
vs_logger_get_loglev(void) {
    return _log_level;
}

/******************************************************************************/
bool
vs_logger_is_loglev(vs_log_level_t level) {

    VS_IOT_ASSERT(_log_level != VS_LOGLEV_UNKNOWN);

    return level <= _log_level;
}

/******************************************************************************/
static const char *
_get_level_str(vs_log_level_t log_level) {

    switch (log_level) {
    case VS_LOGLEV_INFO:
        return "INFO";
    case VS_LOGLEV_FATAL:
        return "FATAL";
    case VS_LOGLEV_ALERT:
        return "ALERT";
    case VS_LOGLEV_CRITICAL:
        return "CRITICAL";
    case VS_LOGLEV_ERROR:
        return "ERROR";
    case VS_LOGLEV_WARNING:
        return "WARNING";
    case VS_LOGLEV_NOTICE:
        return "NOTICE";
    case VS_LOGLEV_TRACE:
        return "TRACE";
    case VS_LOGLEV_DEBUG:
        return "DEBUG";

    default:
        VS_IOT_ASSERT(0 && "Unsupported logging level");
        return "";
    }
}

#define VS_LOGGER_OUTPUT(STR) if(res){ \
    res = vs_logger_output_hal(STR); \
    }

/******************************************************************************/

#if defined(__GNUC__) && VIRGIL_IOT_MCU_BUILD
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
#endif

static bool
_output_preface(vs_log_level_t level, const char *cur_filename, size_t line_num) {
    int str_size = 0;
    const char *level_str = NULL;
    int snprintf_res = 0;
    bool res = true;

    level_str = _get_level_str(level);

    // Output time string
#if VS_IOT_LOGGER_OUTPUT_TIME
    if (!vs_logger_current_time_hal()) {
        return false;
    }
#endif // VS_IOT_LOGGER_OUTPUT_TIME

    // Output level and file
    VS_LOGGER_OUTPUT(" [")
    VS_LOGGER_OUTPUT(level_str)
    VS_LOGGER_OUTPUT("] ")

    if (cur_filename && line_num) {
        VS_LOGGER_OUTPUT(" [");
        VS_LOGGER_OUTPUT(cur_filename);
        VS_LOGGER_OUTPUT(":");

        // Calculate preface string size
        // TODO : snprintf - since C99
        str_size = VS_IOT_SNPRINTF(NULL, 0, "%d] ", (int)line_num) + 1;
    }

    VS_IOT_ASSERT(str_size > 0);
    VS_IOT_ASSERT(str_size <= _max_buf_size);

    // TODO : VAL, variable not at the function begin - since C99
    char stack_buf[str_size];

    // TODO : snprintf - since C99
    if (cur_filename && line_num) {
        snprintf_res = VS_IOT_SNPRINTF(stack_buf, str_size, "%d] ", (int)line_num);
    }

    if (snprintf_res < 0) {
        VS_IOT_ASSERT(0 && "snprintf call error");
        return false;
    }

    // Output string
    VS_LOGGER_OUTPUT(stack_buf);

    return res;
}

/******************************************************************************/
static bool
_no_format(const char *format, bool *output_result) {
    const char *cur_pos;

    VS_IOT_ASSERT(output_result);

    for (cur_pos = format; *cur_pos != '\0'; ++cur_pos) {
        if (*cur_pos != '%') {
            continue;
        }

        if (cur_pos[1] == '\0') {
            break;
        }

        // "%"
        if (cur_pos[1] != '%') {
            return false;
        }

        ++cur_pos;
    }

    // There are no arguments, so no need to call sprintf call
    *output_result &= vs_logger_output_hal(format);
    *output_result &= vs_logger_output_hal(VS_IOT_LOGGER_EOL);
    return true;
}

/******************************************************************************/
bool
vs_logger_message(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *format, ...) {
    static const char *CUTTED_STR = "...";
    static const size_t CUTTED_STR_SIZE = 3;
    va_list args1;
    va_list args2;
    int str_size;
    int snprintf_res;
    bool res = true;
    bool cutted_str = false;

    if (!vs_logger_is_loglev(level)) {
        return true;
    }

    VS_IOT_ASSERT(cur_filename);
    VS_IOT_ASSERT(format);

    if (!_output_preface(level, cur_filename, line_num)) {
        return false;
    }

    // Omit arguments if there are no single "%"
    if(_no_format(format, &res)) {
        return res;
    }

    // Calculate string size
    va_start(args1, format);
    va_copy(args2, args1);

    str_size = VS_IOT_VSNPRINTF(NULL, 0, format, args1) /* format ... */ + 1;

    va_end(args1);

    VS_IOT_ASSERT(str_size > 0);

    if (str_size > _max_buf_size) {
        str_size = _max_buf_size;
    }

    // Allocate stack buffer

    // TODO : VAL, variable not at the function begin - since C99
    char stack_buf[str_size];

    // Make full string

    // TODO : vsnprintf - since C99
    snprintf_res = VS_IOT_VSNPRINTF(stack_buf, str_size, format, args2);

    if (snprintf_res >= 0 && snprintf_res >= str_size) {
        VS_IOT_STRCPY(stack_buf + snprintf_res + str_size - (CUTTED_STR_SIZE + 1 /* '\0' */), CUTTED_STR);
        cutted_str = true;
    } else if (snprintf_res < 0) {
        res = false;
    }

    va_end(args2);

    if(!res){
        goto terminate;
    }

    // Output string
    VS_LOGGER_OUTPUT(stack_buf);

    // EOL
    VS_LOGGER_OUTPUT(VS_IOT_LOGGER_EOL);

    terminate:
    return res && !cutted_str;
}

#if defined(__GNUC__) && VIRGIL_IOT_MCU_BUILD
#pragma GCC diagnostic pop
#endif

#undef VS_LOGGER_OUTPUT

/******************************************************************************/
bool
vs_logger_message_hex(vs_log_level_t level,
                      const char *cur_filename,
                      size_t line_num,
                      const char *prefix,
                      const void *data_buf,
                      const size_t data_size) {
    static const char *HEX_FORMAT = "%02X";
    char buf[3]; // HEX_FORMAT output
    unsigned char *cur_byte;
    size_t pos;
    bool res;

    VS_IOT_ASSERT(prefix);
    VS_IOT_ASSERT(data_buf);
    VS_IOT_ASSERT(data_size);

    if (!vs_logger_is_loglev(level)) {
        return true;
    }

    if (!_output_preface(level, cur_filename, line_num)) {
        return false;
    }

    res = vs_logger_output_hal(prefix);

    cur_byte = (unsigned char *)data_buf;
    for (pos = 0; pos < data_size && res; ++pos, ++cur_byte) {
        VS_IOT_SPRINTF(buf, HEX_FORMAT, *cur_byte);
        res = vs_logger_output_hal(buf);
    }

    if (res) {
        res = vs_logger_output_hal(VS_IOT_LOGGER_EOL);
    }

    return res;
}



#else // VS_IOT_LOGGER_ENABLE



/******************************************************************************/
bool
vs_logger_init(vs_log_level_t log_level, size_t max_buf_size) {
    (void) log_level;
    (void) max_buf_size;

    return true;
}

/******************************************************************************/
vs_log_level_t
vs_logger_set_loglev(vs_log_level_t new_level) {
    (void) new_level;

    return VS_LOGLEV_NO_LOGGER;
}

/******************************************************************************/
vs_log_level_t
vs_logger_get_loglev(void) {
    return VS_LOGLEV_NO_LOGGER;
}

/******************************************************************************/
bool
vs_logger_is_loglev(vs_log_level_t level) {
    return level == VS_LOGLEV_NO_LOGGER;
}

/******************************************************************************/
bool
vs_logger_message(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *format, ...) {
    (void) level;
    (void) cur_filename;
    (void) line_num;
    (void) format;

    return true;
}

/******************************************************************************/
bool
vs_logger_message_hex(vs_log_level_t level,
                      const char *cur_filename,
                      size_t line_num,
                      const char *prefix,
                      const void *data_buf,
                      const size_t data_size) {
    (void) level;
    (void) cur_filename;
    (void) line_num;
    (void) prefix;
    (void) data_buf;
    (void) data_size;

    return true;
}



#endif // VS_IOT_LOGGER_ENABLE
