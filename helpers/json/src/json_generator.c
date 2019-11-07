/*
 * Copyright 2008-2015, Marvell International Ltd.
 * All Rights Reserved.
 */

/*
 * Simple JSON Generator
 */

#include <string.h>
#include <stdio.h>
#include <stdlib-config.h>

#include <virgil/iot/json/json_generator.h>
#include <virgil/iot/json/json_parser.h>
#include <virgil/iot/logger/logger.h>

/* Utility to jump whitespace and cr/lf */
/******************************************************************************/
static const char *
_skip(const char *in) {
    while (in && (unsigned char)*in <= 32)
        in++;
    return in;
}

/******************************************************************************/
static const char *
_rev_skip(const char *in) {
    while (in && (unsigned char)*in <= 32)
        in--;
    return in;
}

#ifdef CONFIG_JSON_FLOAT
/******************************************************************************/
static void
_print_float(float val, short precision, char *str_val, int len_str_val) {
    int val_int, val_frac;
    int scale = 1;
    short pre_tmp = precision;
    char sign[2] = "";

    while (pre_tmp--)
        scale *= 10;

    if (val < 0) {
        val = -val;
        sign[0] = '-';
        sign[1] = '\0';
    }

    val_int = (int)val;
    val_frac = (int)((val - val_int) * scale);

    VS_IOT_SNPRINTF(str_val, len_str_val, "%s%d.%.*d", sign, val_int, precision, val_frac);
}
#else
/******************************************************************************/
static void
_print_float(float val, short precision, char *str_val, size_t len_str_val) {
    VS_IOT_SNPRINTF(str_val, len_str_val, "\"unsupported\"");
}
#endif

/******************************************************************************/
const char *
verify_json_start(const char *buff) {
    buff = _skip(buff);
    if (*buff != '{' && *buff != '[') {
        VS_LOG_ERROR("Invalid JSON document");
        return NULL;
    } else {
        return ++buff;
    }
}

/******************************************************************************/
static int
_verify_buffer_limit(struct json_str *jptr) {
    /*
     * Check for buffer overflow condition here, and then copy remaining
     * data using VS_IOT_SNPRINTF. This makes sure there is no mem corruption in
     * json set operations.
     */
    if (jptr->free_ptr >= (jptr->len - 1)) {
        VS_LOG_ERROR("buffer maximum limit reached");
        return -1;
    } else
        return VS_JSON_ERR_OK;
}

/******************************************************************************/
void
json_str_init(struct json_str *jptr, char *buff, int len) {
    jptr->buff = buff;
    VS_IOT_MEMSET(jptr->buff, 0, len);
    jptr->free_ptr = 0;
    jptr->len = len;
}

/******************************************************************************/
void
json_str_init_no_clear(struct json_str *jptr, char *buff, int len) {
    jptr->buff = buff;
    jptr->free_ptr = 0;
    jptr->len = len;
}

/******************************************************************************/
void
json_str_finish(struct json_str *jptr) {
    jptr->buff[jptr->free_ptr] = 0;
}

/******************************************************************************/
int
json_push_object(struct json_str *jptr, const char *name) {
    char *buff;

    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    /* From last skip cr/lf */
    buff = (char *)_rev_skip(&jptr->buff[jptr->free_ptr - 1]);
    if (*buff != '{') /* Element in object */
        jptr->buff[jptr->free_ptr++] = ',';

    VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"%s\":{", name);

    jptr->free_ptr = VS_IOT_STRLEN(jptr->buff);
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
int
json_push_array_object(struct json_str *jptr, const char *name) {
    char *buff;

    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    /* From last skip cr/lf */
    buff = (char *)_rev_skip(&jptr->buff[jptr->free_ptr - 1]);
    if (*buff != '{') /* Element in object */
        jptr->buff[jptr->free_ptr++] = ',';

    VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"%s\":[", name);

    jptr->free_ptr = VS_IOT_STRLEN(jptr->buff);
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
int
json_start_object(struct json_str *jptr) {
    char *buff;

    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    if (jptr->free_ptr) {
        /* This should be first call after json_str_init so free_ptr
         * should be 0 but if it is not then we add ',' before
         * starting object as there could have been earlier object
         * already present as case in array.
         */
        /* From last skip cr/lf */
        buff = (char *)_rev_skip(&jptr->buff[jptr->free_ptr - 1]);

        if (*buff == '}')
            jptr->buff[jptr->free_ptr++] = ',';
    }
    jptr->buff[jptr->free_ptr++] = '{';
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
int
json_close_object(struct json_str *jptr) {
    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    jptr->buff[jptr->free_ptr++] = '}';

    return VS_JSON_ERR_OK;
}

/******************************************************************************/
int
json_pop_array_object(struct json_str *jptr) {
    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    jptr->buff[jptr->free_ptr++] = ']';

    return VS_JSON_ERR_OK;
}

/******************************************************************************/
int
json_start_array(struct json_str *jptr) {
    char *buff;
    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    /* From last skip cr/lf */
    buff = (char *)_rev_skip(&jptr->buff[jptr->free_ptr - 1]);

    if (*buff == ']')
        jptr->buff[jptr->free_ptr++] = ',';

    jptr->buff[jptr->free_ptr++] = '[';
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
int
json_close_array(struct json_str *jptr) {
    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    jptr->buff[jptr->free_ptr++] = ']';
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
int
json_set_array_value(struct json_str *jptr, char *str, int value, float val, json_data_types data) {
    char *buff;

    if (!verify_json_start(jptr->buff))
        return WM_E_JSON_INVSTART;

    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    /* From last skip cr/lf */
    buff = (char *)_rev_skip(&jptr->buff[jptr->free_ptr - 1]);

    if (*buff != '[') /* Element in object */
        jptr->buff[jptr->free_ptr++] = ',';

    switch (data) {
    case JSON_VAL_STR:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"%s\"", str);
        break;
    case JSON_VAL_INT:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "%d", value);
        break;
    case JSON_VAL_FLOAT:
        _print_float(val, 2, &jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr);
        break;
    case JSON_VAL_BOOL:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "%s", (value == 1) ? "true" : "false");
        break;
    default:
        VS_LOG_ERROR("Invalid case in array set");
    }

    jptr->free_ptr = VS_IOT_STRLEN(jptr->buff);
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
int
json_set_object_value(struct json_str *jptr,
                      const char *name,
                      const char *str,
                      int64_t value,
                      float val,
                      short precision,
                      json_data_types data) {
    char *buff;

    if (!verify_json_start(jptr->buff))
        return -WM_E_JSON_INVSTART;

    if (_verify_buffer_limit(jptr) < 0)
        return -WM_E_JSON_OBUF;

    /* From last skip cr/lf */
    buff = (char *)_rev_skip(&jptr->buff[jptr->free_ptr - 1]);

    if (*buff != '{') /* Element in object */
        jptr->buff[jptr->free_ptr++] = ',';

    switch (data) {
    case JSON_VAL_STR:
        /* First, check if the string can fit into the buffer.
         * The + 6 is used to account for "":"" and NULL termintaion
         */
        if ((VS_IOT_STRLEN(str) + VS_IOT_STRLEN(name) + 6) > (jptr->len - jptr->free_ptr))
            return -WM_E_JSON_OBUF;

        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"%s\":\"", name);
        jptr->free_ptr = VS_IOT_STRLEN(jptr->buff);
        /* We use memmove in order to allow the source and destination
         * strings to overlap
         */
        VS_IOT_MEMMOVE(&jptr->buff[jptr->free_ptr], str, VS_IOT_STRLEN(str) + 1);
        jptr->free_ptr = VS_IOT_STRLEN(jptr->buff);
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"");
        break;

    case JSON_VAL_INT:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"%s\":%d", name, (int)value);
        break;

    case JSON_VAL_UINT:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"%s\":%u", name, (unsigned)value);
        break;

    case JSON_VAL_UINT_64:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr],
                        jptr->len - jptr->free_ptr,
                        "\"%s\":%llu",
                        name,
                        (unsigned long long)value);
        break;

    case JSON_VAL_FLOAT:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"%s\":", name);
        jptr->free_ptr = VS_IOT_STRLEN(jptr->buff);
        _print_float(val, precision, &jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr);
        break;
    case JSON_VAL_BOOL:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr],
                        jptr->len - jptr->free_ptr,
                        "\"%s\":%s",
                        name,
                        (value == 1) ? "true" : "false");
        break;
    case JSON_VAL_NULL:
        VS_IOT_SNPRINTF(&jptr->buff[jptr->free_ptr], jptr->len - jptr->free_ptr, "\"%s\":null", name);
        break;
    default:
        VS_LOG_ERROR("Invalid case in object set");
    }

    jptr->free_ptr = VS_IOT_STRLEN(jptr->buff);
    return VS_JSON_ERR_OK;
}
