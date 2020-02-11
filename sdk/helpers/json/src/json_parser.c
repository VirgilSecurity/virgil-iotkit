/*
 *  Copyright (C) 2008-2016, Marvell International Ltd.
 *  All Rights Reserved.
 *
 *  Derived from:
 *  http://zserge.com/jsmn.html
 */
#include <stdbool.h>
#include <string.h>
#include <global-hal.h>
#include <stdlib-config.h>
#include <virgil/iot/json/json_parser.h>

#ifndef JSMN_PARENT_LINKS
#error JSON Parser requires JSMN_PARENT_LINKS
#endif

#ifndef JSMN_STRICT
#error JSON Parser requires JSMN_STRICT
#endif

/******************************************************************************/
/* Returns true if an exact string match is found, else false */
static bool
_json_token_streq(char *js, jsontok_t *t, char *s) {
    return (VS_IOT_STRNCMP(js + t->start, s, t->end - t->start) == 0 &&
            VS_IOT_STRLEN(s) == (size_t)(t->end - t->start));
}

/******************************************************************************/
/* Skips to the last element of an array or object.
 * If there is an array/object inside the given array/object,
 * the function is called recursively to skip all elements
 */
static jsontok_t *
_skip_to_last(jsontok_t *element) {
    jsontok_t *t = element;
    if (t->size == 0)
        return t;
    int cnt = t->size;
    while (cnt--) {
        t++;
        if (t->size)
            t = _skip_to_last(t);
    }
    return t;
}

/******************************************************************************/
/* Converts the value held by the token into a boolean */
static int
_json_str_to_bool(jobj_t *jobj, jsontok_t *t, bool *value) {
    if (!t || t->type != JSMN_PRIMITIVE)
        return -WM_E_JSON_INVALID_TYPE;
    if (_json_token_streq(jobj->js, t, "true") || _json_token_streq(jobj->js, t, "1"))
        *value = true;
    else if (_json_token_streq(jobj->js, t, "false") || _json_token_streq(jobj->js, t, "0"))
        *value = false;
    else
        return -WM_E_JSON_INVALID_TYPE;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Converts the value held by the token into an integer */
static int
_json_str_to_int(jobj_t *jobj, jsontok_t *t, int *value) {
    if (!t || t->type != JSMN_PRIMITIVE)
        return -WM_E_JSON_INVALID_TYPE;
    char *endptr;
    int int_val = (int)strtoul(&jobj->js[t->start], &endptr, 10);
    if (endptr == &(jobj->js[t->end])) {
        *value = int_val;
        return VS_JSON_ERR_OK;
    } else {
        return -WM_E_JSON_INVALID_TYPE;
    }
}

/******************************************************************************/
/* Converts the value held by the token into an int64 */
static int
_json_str_to_int64(jobj_t *jobj, jsontok_t *t, int64_t *value) {
    if (!t || t->type != JSMN_PRIMITIVE)
        return -WM_E_JSON_INVALID_TYPE;
    char *endptr;
    int64_t int_val = strtoull(&jobj->js[t->start], &endptr, 10);
    if (endptr == &(jobj->js[t->end])) {
        *value = int_val;
        return VS_JSON_ERR_OK;
    } else {
        return -WM_E_JSON_INVALID_TYPE;
    }
}
#ifdef CONFIG_JSON_FLOAT
/******************************************************************************/
/* Converts the value held by the token into a float */
static int
_json_str_to_float(jobj_t *jobj, jsontok_t *t, float *value) {
    if (!t || t->type != JSMN_PRIMITIVE)
        return -WM_E_JSON_INVALID_TYPE;
    char *start_ptr = &jobj->js[t->start];
    char *endptr;

    *value = wm_strtof(start_ptr, &endptr);
    if (endptr != &(jobj->js[t->end]))
        return -WM_E_JSON_INVALID_TYPE;
    return 0;
}
#endif /* CONFIG_JSON_FLOAT */

/******************************************************************************/
/* Converts the value held by the token into a null terminated string */
static int
_json_str_to_str(jobj_t *jobj, jsontok_t *t, char *value, int maxlen) {
    if (!t || t->type != JSMN_STRING)
        return -WM_E_JSON_INVALID_TYPE;
    if ((t->end - t->start) >= maxlen)
        return -WM_E_JSON_NOMEM;
    VS_IOT_STRNCPY(value, jobj->js + t->start, t->end - t->start);
    value[t->end - t->start] = 0;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Searches for json element inside an object based on the key and populates
 * the val_t token if element is found and returns 0.
 * If not found, returns error.
 */
static int
_json_get_value(jobj_t *jobj, char *key, jsontok_t **val_t) {
    jsontok_t *t = jobj->cur;
    int num_children = t->size;
    *val_t = NULL;
    /* If there are no children it is an error, since we
     * would not find the key at all
     */
    if (num_children == 0)
        return -WM_E_JSON_FAIL;

    /* If the current token type is not an object, it is an error */
    if (t->type != JSMN_OBJECT)
        return -WM_E_JSON_INVALID_JOBJ;
    while (num_children--) {
        /* Increment the token pointer first so that we begin from the
         * first token inside the object.
         */
        t++;
        /* For safety, check if the current token's end does not go
         * beyond the parent object's end. This case is unlikely, yet,
         * better to have a check.
         */
        if (t->end > jobj->cur->end)
            return -WM_E_JSON_FAIL;
        /* First token inside an object should be a key.
         * If not, it is an error.
         */
        if (t->type != JSMN_STRING)
            return -WM_E_JSON_FAIL;
        /* If the key matches with the given key, the member
         * has been found.
         * Else, just skip the value.
         */
        if (_json_token_streq(jobj->js, t, key)) {
            /* Value found. The next token has the value.
             * Populate the token pointer and return success.
             */
            t++;
            *val_t = t;
            return VS_JSON_ERR_OK;
        } else {
            /* Skip the value token since this is not the
             * key that we were looking for
             */
            t++;
            t = _skip_to_last(t);
        }
    }
    return -WM_E_JSON_NOT_FOUND;
}

/******************************************************************************/
/* Search boolean value based on given key */
int
json_get_val_bool(jobj_t *jobj, char *key, bool *value) {
    jsontok_t *t;
    int ret = _json_get_value(jobj, key, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    return _json_str_to_bool(jobj, t, value);
}

/******************************************************************************/
/* Search integer value based on given key */
int
json_get_val_int(jobj_t *jobj, char *key, int *value) {
    jsontok_t *t;
    int ret = _json_get_value(jobj, key, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    return _json_str_to_int(jobj, t, value);
}

/******************************************************************************/
/* Search int64 value based on given key */
int
json_get_val_int64(jobj_t *jobj, char *key, int64_t *value) {
    jsontok_t *t;
    int ret = _json_get_value(jobj, key, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    return _json_str_to_int64(jobj, t, value);
}

/******************************************************************************/
/* Search float value based on given key */
#ifdef CONFIG_JSON_FLOAT
int
json_get_val_float(jobj_t *jobj, char *key, float *value) {
    jsontok_t *t;
    int ret = json_get_value(jobj, key, &t);
    if (ret != 0)
        return ret;
    return _json_str_to_float(jobj, t, value);
}
#else
int
json_get_val_float(jobj_t *jobj, char *key, float *value) {
    return -WM_E_JSON_FAIL;
}
#endif /* CONFIG_JSON_FLOAT */

/******************************************************************************/
/* Search string value based on given key */
int
json_get_val_str(jobj_t *jobj, char *key, char *value, int maxlen) {
    jsontok_t *t;
    int ret = _json_get_value(jobj, key, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    return _json_str_to_str(jobj, t, value, maxlen);
}

/******************************************************************************/
int
json_get_val_str_len(jobj_t *jobj, char *key, int *len) {
    jsontok_t *t;
    int ret = _json_get_value(jobj, key, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    if (!t || t->type != JSMN_STRING)
        return -WM_E_JSON_INVALID_TYPE;
    *len = t->end - t->start;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Search composite object based on given key */
int
json_get_composite_object(jobj_t *jobj, char *key) {
    jsontok_t *t;
    int ret = _json_get_value(jobj, key, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    if (!t || t->type != JSMN_OBJECT)
        return -WM_E_JSON_INVALID_TYPE;
    /* Reduce the scope of subsequent searches to this object */
    jobj->cur = t;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Release a composite object*/
int
json_release_composite_object(jobj_t *jobj) {
    if (jobj->cur->parent < 0)
        return -WM_E_JSON_FAIL;
    /* The parent of the current element will be its "key" */
    jobj->cur = &jobj->tokens[jobj->cur->parent];

    if (jobj->cur->parent < 0)
        return -WM_E_JSON_FAIL;
    /* The parent of the key will be the actual parent object/array */
    jobj->cur = &jobj->tokens[jobj->cur->parent];
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Search array object based on given key */
int
json_get_array_object(jobj_t *jobj, char *key, int *num_elements) {
    jsontok_t *t;
    int ret = _json_get_value(jobj, key, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    if (!t || t->type != JSMN_ARRAY)
        return -WM_E_JSON_INVALID_TYPE;
    /* Reduce the scope of subsequent searches to this array */
    jobj->cur = t;
    /* Indicate the number of array elements found, if requested */
    if (num_elements)
        *num_elements = t->size;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Release array object */
int
json_release_array_object(jobj_t *jobj) {
    return json_release_composite_object(jobj);
}

/******************************************************************************/
int
json_array_get_num_elements(jobj_t *jobj) {
    if (jobj->cur->type != JSMN_ARRAY)
        return -WM_E_JSON_FAIL;
    return jobj->cur->size;
}

/******************************************************************************/
/* Fetch the JSON value from an array based on index.
 * val_t is appropriately populated if the element is found
 * and 0 is returned. Else error is returned.
 */
static int
_json_get_array_index(jobj_t *jobj, uint16_t index, jsontok_t **val_t) {
    *val_t = NULL;
    if (jobj->cur->type != JSMN_ARRAY)
        return -WM_E_JSON_INVALID_JARRAY;
    /* Given index exceeds the size of array. */
    if (index >= jobj->cur->size)
        return -WM_E_JSON_INVALID_INDEX;
    jsontok_t *t = jobj->cur;
    /* Incrementing once so that the token pointer points to index 0*/
    t++;
    while (index--) {
        /* For safety, check if the current token's end does not go
         * beyond the parent object's end. This case is unlikely, yet,
         * better to have a check.
         */
        if (t->end > jobj->cur->end)
            return -WM_E_JSON_FAIL;
        /* If the element is an array or object, skip to its last
         * element.
         */
        if (t->type == JSMN_ARRAY || t->type == JSMN_OBJECT)
            t = _skip_to_last(t);
        t++;
    }
    *val_t = t;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Search boolean value inside an array based on given index */
int
json_array_get_bool(jobj_t *jobj, uint16_t index, bool *value) {
    jsontok_t *t;
    int ret = _json_get_array_index(jobj, index, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    return _json_str_to_bool(jobj, t, value);
}

/******************************************************************************/
/* Search integer value inside an array based on given index */
int
json_array_get_int(jobj_t *jobj, uint16_t index, int *value) {
    jsontok_t *t;
    int ret = _json_get_array_index(jobj, index, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    return _json_str_to_int(jobj, t, value);
}

/******************************************************************************/
/* Search int64 value inside an array based on given index */
int
json_array_get_int64(jobj_t *jobj, uint16_t index, int64_t *value) {
    jsontok_t *t;
    int ret = _json_get_array_index(jobj, index, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    return _json_str_to_int64(jobj, t, value);
}

/******************************************************************************/
/* Search float value inside an array based on given index */
#ifdef CONFIG_JSON_FLOAT
int
json_array_get_float(jobj_t *jobj, uint16_t index, float *value) {
    jsontok_t *t;
    int ret = json_get_array_index(jobj, index, &t);
    if (ret != 0)
        return ret;
    return json_str_to_float(jobj, t, value);
}
#else
int
json_array_get_float(jobj_t *jobj, uint16_t index, float *value) {
    return -WM_E_JSON_FAIL;
}
#endif /* CONFIG_JSON_FLOAT */

/******************************************************************************/
/* Search string value inside an array based on given index */
int
json_array_get_str(jobj_t *jobj, uint16_t index, char *value, int maxlen) {
    jsontok_t *t;
    int ret = _json_get_array_index(jobj, index, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    return _json_str_to_str(jobj, t, value, maxlen);
}

/******************************************************************************/
int
json_array_get_str_len(jobj_t *jobj, uint16_t index, int *len) {
    jsontok_t *t;
    int ret = _json_get_array_index(jobj, index, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    if (!t || t->type != JSMN_STRING)
        return -WM_E_JSON_INVALID_TYPE;
    *len = t->end - t->start;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Search composite object inside an array based on given index */
int
json_array_get_composite_object(jobj_t *jobj, uint16_t index) {
    jsontok_t *t;
    int ret = _json_get_array_index(jobj, index, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    if (!t || t->type != JSMN_OBJECT)
        return -WM_E_JSON_INVALID_TYPE;
    jobj->cur = t;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Release the composite object inside the array */
int
json_array_release_composite_object(jobj_t *jobj) {
    if (jobj->cur->parent < 0)
        return -WM_E_JSON_FAIL;
    /* The parent of the current element will be the array */
    jobj->cur = &jobj->tokens[jobj->cur->parent];

    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Search an array inside an array based on given index */
int
json_array_get_array_object(jobj_t *jobj, uint16_t index, int *num_elements) {
    jsontok_t *t;
    int ret = _json_get_array_index(jobj, index, &t);
    if (ret != VS_JSON_ERR_OK)
        return ret;
    if (!t || t->type != JSMN_ARRAY)
        return -WM_E_JSON_INVALID_TYPE;
    jobj->cur = t;
    *num_elements = t->size;
    return VS_JSON_ERR_OK;
}

/******************************************************************************/
/* Release the array */
int
json_array_release_array_object(jobj_t *jobj) {
    return json_array_release_composite_object(jobj);
}

/******************************************************************************/
/* Initialize the JSON parser */
static void
_json_obj_init(jobj_t *jobj, jsontok_t *tokens, int num_tokens) {
    jobj->js = NULL;
    jobj->tokens = tokens;
    jobj->num_tokens = num_tokens;
    jobj->cur = NULL;
    jsmn_init(&jobj->parser);
}


/******************************************************************************/
bool
json_is_object(jobj_t *jobj) {
    if (jobj->cur->type == JSMN_OBJECT)
        return true;
    else
        return false;
}

/******************************************************************************/
bool
json_is_array(jobj_t *jobj) {
    if (jobj->cur->type == JSMN_ARRAY)
        return true;
    else
        return false;
}

/******************************************************************************/
static bool
_json_is_valid(jobj_t *jobj, jsmnenumtype_t type) {
    jsontok_t *t = jobj->cur;
    /* If the current token type itself is not correct, return false*/
    if (t->type != type)
        return false;

    int num_children = t->size;
    /* If there are no children it is an error */
    if (num_children == 0) {
        return true;
    }

    while (num_children--) {
        /* Increment the token pointer first so that we begin from the
         * first token inside the object.
         */
        t++;
        /* For safety, check if the current token's end does not go
         * beyond the parent object's end. This case is unlikely, yet,
         * better to have a check.
         */
        if (t->end > jobj->cur->end)
            return false;
        if (jobj->cur->type == JSMN_OBJECT) {
            /* First token inside an object should be a key.
             * If not, it is an error.
             */
            if (t->type != JSMN_STRING)
                return false;
            /* If the key does not have a corresponding value,
             * or has multiple children, return an error.
             */
            if (t->size != 1)
                return false;
            /* Skip to value token so that we can validate the value
             */
            t++;
        }
        if ((t->type == JSMN_OBJECT) || (t->type == JSMN_ARRAY)) {
            jsontok_t *tmp_tok = jobj->cur;
            jobj->cur = t;
            bool valid = _json_is_valid(jobj, t->type);
            jobj->cur = tmp_tok;
            if (!valid)
                return false;
        } else if (t->size) {
            /* If the element is neither an object,
             * nor an array, it cannot have any children.
             * If it has, return error
             */
            return false;
        }
        t = _skip_to_last(t);
    }
    return true;
}

/******************************************************************************/
static bool
_json_is_array_valid(jobj_t *jobj) {
    return _json_is_valid(jobj, JSMN_ARRAY);
}

/******************************************************************************/
static bool
_json_is_object_valid(jobj_t *jobj) {
    return _json_is_valid(jobj, JSMN_OBJECT);
}

/******************************************************************************/
/* Parse the given JSON string */
int
json_init(jobj_t *jobj, jsontok_t *tokens, int num_tokens, char *js, size_t js_len) {
    _json_obj_init(jobj, tokens, num_tokens);
    int parsed_tokens = jsmn_parse(&jobj->parser, js, js_len, jobj->tokens, jobj->num_tokens);
    if (parsed_tokens < 0) {
        switch (parsed_tokens) {
        case JSMN_ERROR_NOMEM:
            return -WM_E_JSON_NOMEM;
        case JSMN_ERROR_INVAL:
            return -WM_E_JSON_INVAL;
        case JSMN_ERROR_PART:
            return -WM_E_JSON_INCOMPLETE;
        default:
            return -WM_E_JSON_FAIL;
        }
    }
    jobj->js = js;
    jobj->num_tokens = parsed_tokens;
    jobj->cur = jobj->tokens;
    if (jobj->tokens->type == JSMN_OBJECT) {
        if (_json_is_object_valid(jobj))
            return VS_JSON_ERR_OK;
        else
            return -WM_E_JSON_INVALID_JOBJ;
    } else if (jobj->tokens->type == JSMN_ARRAY) {
        if (_json_is_array_valid(jobj))
            return VS_JSON_ERR_OK;
        else
            return -WM_E_JSON_INVALID_JARRAY;
    } else
        return -WM_E_JSON_INVALID_JOBJ;
}

/******************************************************************************/
int
json_parse_start(jobj_t *jobj, char *js, size_t js_len) {
    /* Passing NULL for tokens gives us the total number of tokens that
     * will be required to parse the string successfully.
     */
    _json_obj_init(jobj, NULL, 0);
    int parsed_tokens = jsmn_parse(&jobj->parser, js, js_len, jobj->tokens, jobj->num_tokens);
    if (parsed_tokens < 0) {
        switch (parsed_tokens) {
        case JSMN_ERROR_NOMEM:
            return -WM_E_JSON_NOMEM;
        case JSMN_ERROR_INVAL:
            return -WM_E_JSON_INVAL;
        case JSMN_ERROR_PART:
            return -WM_E_JSON_INCOMPLETE;
        default:
            return -WM_E_JSON_FAIL;
        }
    }
    jsontok_t *tokens = VS_IOT_MALLOC(parsed_tokens * sizeof(jsontok_t));
    if (!tokens)
        return -WM_E_JSON_NOMEM;

    int ret = json_init(jobj, tokens, parsed_tokens, js, js_len);
    if (ret != VS_JSON_ERR_OK)
        json_parse_stop(jobj);

    return ret;
}

/******************************************************************************/
void
json_parse_stop(jobj_t *jobj) {
    if (jobj->tokens)
        VS_IOT_FREE(jobj->tokens);
}
