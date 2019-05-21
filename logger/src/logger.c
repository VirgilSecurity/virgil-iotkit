#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <logger.h>
#include <logger_hal.h>

#define ASSERT assert

static vs_log_level_t _log_level = VS_LOGLEV_UNKNOWN;
static bool _use_heap_buffer = false;
static size_t _max_buf_size = 0;

/******************************************************************************/
bool
vs_logger_init(vs_log_level_t log_level, bool use_heap_buffer, size_t max_buf_size){
    vs_logger_set_loglev(log_level);

    _use_heap_buffer = use_heap_buffer;
    _max_buf_size = max_buf_size;
    if(!max_buf_size)
        return false;

    return true;
}

/******************************************************************************/
vs_log_level_t
vs_logger_set_loglev(vs_log_level_t new_level){
    vs_log_level_t prev_level = _log_level;

    _log_level = new_level;

    return prev_level;
}

/******************************************************************************/
vs_log_level_t
vs_logger_get_loglev(void){
    return _log_level;
}

/******************************************************************************/
bool
vs_logger_is_loglev(vs_log_level_t level){

    ASSERT(_log_level != VS_LOGLEV_UNKNOWN);

    return level <= _log_level;
}

/******************************************************************************/
static const char *
_get_level_str(vs_log_level_t log_level){

    switch(log_level){
    case VS_LOGLEV_INFO : return "INFO";
    case VS_LOGLEV_FATAL : return "FATAL";
    case VS_LOGLEV_ALERT : return "ALERT";
    case VS_LOGLEV_CRITICAL : return "CRITICAL";
    case VS_LOGLEV_ERROR : return "ERROR";
    case VS_LOGLEV_WARNING : return "WARNING";
    case VS_LOGLEV_NOTICE : return "NOTICE";
    case VS_LOGLEV_TRACE : return "TRACE";
    case VS_LOGLEV_DEBUG : return "DEBUG";

    default : ASSERT(false && "Unsupported logging level"); return "";
    }
}

/******************************************************************************/
bool
vs_logger_message(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *format, ...){
    time_t time_tmp;
    static const size_t TIME_STR_SIZE = 26;
    char time_buf[TIME_STR_SIZE];
    static const char *CUTTED_STR = "...\n";
    static const size_t CUTTED_STR_SIZE = 4;
    va_list args1;
    va_list args2;
    int str_size;
    const char *level_str = NULL;
    char *output_str = NULL;
    char *cur_pos = NULL;
    size_t stack_buf_size = 0;
    int snprintf_res;
    bool res = false;
    bool cutted_str = false;

    if(!vs_logger_is_loglev(level))
        return true;

    ASSERT(cur_filename);
    ASSERT(format);

    level_str = _get_level_str(level);

    // Make time string
    time(&time_tmp);
    strftime(time_buf, TIME_STR_SIZE, "%Y-%m-%d %H:%M:%S:", localtime(&time_tmp));

    // Calculate full string size
    va_start(args1, format);
    va_copy(args2, args1);

    str_size = vsnprintf(NULL, 0, format, args1) /* format ... */;

    va_end(args1);

    ASSERT(str_size > 0);

    str_size += TIME_STR_SIZE /* cur_time_buf */ + 3+strlen(level_str) /* " [level_str]" */ +
                3+strlen(cur_filename) + /*" [cur_filename:" */ + 8 /* "line_num] " */ + 2 /* "\n" */;

    if(str_size > _max_buf_size)
        str_size = _max_buf_size;

    // Allocate heap or stack vuffer
    if(!_use_heap_buffer) {
        stack_buf_size = str_size;
    }

    char stack_buf[stack_buf_size];
    output_str = stack_buf;

    if(_use_heap_buffer){
        output_str = malloc(str_size);
    }

    // Make full string
    cur_pos = output_str;
    snprintf_res = snprintf(cur_pos, str_size, "%s [%s] [%s:%d] ", time_buf, level_str, cur_filename, (int)line_num);
    if(snprintf_res >= 0 && snprintf_res < str_size){
        cur_pos += snprintf_res;
        str_size -= snprintf_res;
    } else {
        cutted_str = true;
    }

    if(!cutted_str) {
        snprintf_res = vsnprintf(cur_pos, str_size, format, args2);

        if (snprintf_res >= 0 && snprintf_res < str_size) {
            cur_pos += snprintf_res;
            strcpy(cur_pos, "\n");
        } else {
            cutted_str = true;
        }
    }

    va_end(args2);

    // Cut string if necessary
    if(cutted_str) {
        cur_pos += str_size;
        strcpy(cur_pos - (CUTTED_STR_SIZE + 1 /* '\0' */), CUTTED_STR);
    }

    // Output string
    res = vs_logger_print_hal(output_str);

    if(_use_heap_buffer)
        free(output_str);

    return res && !cutted_str;
}

/******************************************************************************/
bool
vs_logger_message_hex(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *prefix, const void *data_buf, const size_t data_size){
    char *buf = NULL;
    char *cur_pos;
    size_t pos;
    bool res;
    const unsigned char *data_ptr = data_buf;

    ASSERT(cur_filename);
    ASSERT(prefix);
    ASSERT(data_buf && data_size);

    if(!vs_logger_is_loglev(level))
        return true;

    buf = malloc(data_size * 3 /* "FE " */ + 1);

    if(!buf){
        ASSERT(false);
        return false;
    }

    cur_pos = buf;
    for(pos = 0; pos < data_size; ++pos, ++data_ptr){
        cur_pos += sprintf(cur_pos, "%02X ", *data_ptr);
    }

    res = vs_logger_message(level, cur_filename, line_num, "%s : %s", prefix, buf);

    free(buf);

    return res;
}
