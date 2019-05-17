#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <logger.h>
#include <hal/macro.h>

static vs_log_level_t _log_level = VS_LOGLEV_UNKNOWN;

/******************************************************************************/
bool
vs_logger_init(vs_log_level_t log_level){
    vs_logger_set_loglev(log_level);

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

            VS_ASSERT(_log_level != VS_LOGLEV_UNKNOWN);

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

    default : VS_ASSERT(false && "Unsupported logging level"); return "";
    }
}

/******************************************************************************/
bool
vs_logger_message(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *format, ...){
    time_t time_tmp;
    static const size_t TIME_STR_SIZE = 26;
    char time_buf[TIME_STR_SIZE];
    va_list args1;
    va_list args2;
    int str_size;
    const char *level_str = NULL;
    char *output_str = NULL;
    char *cur_pos = NULL;
    char local_buf[256];
    bool is_local_buf;
    int errnum;
    bool res = false;

    if(!vs_logger_is_loglev(level))
        return true;

            VS_ASSERT(cur_filename);
            VS_ASSERT(format);

    level_str = _get_level_str(level);

    time(&time_tmp);
    strftime(time_buf, TIME_STR_SIZE, "%Y-%m-%d %H:%M:%S:", localtime(&time_tmp));

    va_start(args1, format);
    va_copy(args2, args1);

    str_size = vsnprintf(NULL, 0, format, args1) /* format ... */;

            VS_ASSERT(str_size > 0);

    str_size += TIME_STR_SIZE /* cur_time_buf */ + 3+strlen(level_str) /* " [level_str]" */ +
                3+strlen(cur_filename) + /*" [cur_filename:" */ + 8 /* "line_num] " */ + 1 /* '\0' */;

    if(str_size <= sizeof(local_buf)){
        output_str = local_buf;
        is_local_buf = true;
    } else {
        output_str = malloc(str_size);
                VS_ASSERT(output_str);
        is_local_buf = false;
    }

    va_end(args1);

    cur_pos = output_str;
    cur_pos += sprintf(cur_pos, "%s [%s] [%s:%d] ", time_buf, level_str, cur_filename, (int)line_num);
    errnum = vsprintf(cur_pos, format, args2);
    if(errnum >= 0){
        cur_pos += errnum;
        sprintf(cur_pos, "\n");
        res = vs_logger_print_hal(output_str);
    } else {
                VS_ASSERT(false);
    }

    va_end(args2);

    if(!is_local_buf)
        free(output_str);

    return res;
}

/******************************************************************************/
bool
vs_logger_message_hex(vs_log_level_t level, const char *cur_filename, size_t line_num, const char *prefix, const void *data_buf, const size_t data_size){
    char *buf = NULL;
    char *cur_pos;
    size_t pos;
    bool res;
    const unsigned char *data_ptr = data_buf;

            VS_ASSERT(cur_filename);
            VS_ASSERT(prefix);
            VS_ASSERT(data_buf && data_size);

    if(!vs_logger_is_loglev(level))
        return true;

    buf = malloc(data_size * 3 /* "FE " */ + 1);

    if(!buf){
                VS_ASSERT(false);
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