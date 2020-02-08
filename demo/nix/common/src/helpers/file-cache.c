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

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "helpers/file-cache.h"

#define VS_FILE_CACHE_SZ (40)
#define VS_FILE_CACHE_MAX_FILE_SZ (2 * 1024 * 1024)

typedef struct {
    char *fn;
    uint8_t *data;
    size_t file_sz;
    time_t last_usage_time;
} vs_file_cache_element_t;

typedef struct {
    vs_file_cache_element_t elements[VS_FILE_CACHE_SZ];
    bool enabled;
} vs_file_cache_ctx_t;

static vs_file_cache_ctx_t _ctx = {.enabled = false};
static pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;

/******************************************************************************/
static void
_safe_mutex_lock(pthread_mutex_t *mutex) {
    int ret = pthread_mutex_lock(mutex);
    if (ret != 0) {
        fprintf(stderr, "pthread_mutex_lock error [%d]! Aborting immediately!\n", ret);
        exit(1);
    }
}

/******************************************************************************/
static void
_safe_mutex_unlock(pthread_mutex_t *mutex) {
    int ret = pthread_mutex_unlock(mutex);
    if (ret != 0) {
        fprintf(stderr, "pthread_mutex_unlock error [%d]! Aborting immediately!\n", ret);
        exit(1);
    }
}

/******************************************************************************/
static void
_free_element(vs_file_cache_element_t *element) {
    if (!element) {
        return;
    }
    free(element->fn);
    free(element->data);
    memset(element, 0, sizeof(vs_file_cache_element_t));
}

/******************************************************************************/
static vs_file_cache_element_t *
_find_element(const char *file_name) {
    int i;
    assert(file_name && *file_name);
    if (!file_name || !*file_name) {
        return NULL;
    }
    for (i = 0; i < VS_FILE_CACHE_SZ; i++) {
        if (!_ctx.elements[i].fn)
            continue;
        if (0 == strcmp(file_name, _ctx.elements[i].fn)) {
            return &_ctx.elements[i];
        }
    }

    return NULL;
}

/******************************************************************************/
static vs_file_cache_element_t *
_element_to_add(void) {
    int i;
    vs_file_cache_element_t *oldest_element = NULL;

    for (i = 0; i < VS_FILE_CACHE_SZ; i++) {
        if (!_ctx.elements[i].fn) {
            return &_ctx.elements[i];
        }

        if (!oldest_element || _ctx.elements[i].last_usage_time < oldest_element->last_usage_time) {
            oldest_element = &_ctx.elements[i];
        }
    }

    _free_element(oldest_element);

    return oldest_element;
}

/******************************************************************************/
void
_file_cache_close_internal(const char *file_name) {
    vs_file_cache_element_t *element;
    element = _find_element(file_name);

    if (element) {
        _free_element(element);
    }
}

/******************************************************************************/
int
_read_file(const char *file_name, vs_file_cache_element_t *element) {
    FILE *fp = NULL;
    int res = -1;

    assert(file_name && *file_name && element);
    if (!file_name || !*file_name || !element) {
        return -1;
    }

    element->last_usage_time = time(NULL);
    element->fn = strdup(file_name);

    fp = fopen(file_name, "rb");

    if (!fp) {
        goto terminate;
    }

    fseek(fp, 0, SEEK_END);
    element->file_sz = ftell(fp);

    if (element->file_sz >= VS_FILE_CACHE_MAX_FILE_SZ) {
        goto terminate;
    }

    element->data = malloc(element->file_sz);

    if (!element->data) {
        goto terminate;
    }

    fseek(fp, 0, SEEK_SET);
    if (1 == fread(element->data, element->file_sz, 1, fp)) {
        res = 0;
    }

terminate:

    if (fp) {
        fclose(fp);
    }

    if (0 != res) {
        _free_element(element);
    }

    return res;
}

/******************************************************************************/
int
vs_file_cache_enable(bool enable) {
    _safe_mutex_lock(&_lock);
    {
        if (enable) {
            memset(&_ctx, 0, sizeof(_ctx));
            _ctx.enabled = true;
        } else {
            if (_ctx.enabled) {
                vs_file_cache_clean();
            }
            _ctx.enabled = false;
        }
    }
    _safe_mutex_unlock(&_lock);

    return 0;
}

/******************************************************************************/
int
vs_file_cache_open(const char *file_name) {
    vs_file_cache_element_t *element;
    int res = -1;
    _safe_mutex_lock(&_lock);
    {
        if (_ctx.enabled) {
            element = _find_element(file_name);
            if (element) {
                // Update last usage time
                element->last_usage_time = time(NULL);
                res = 0;
            } else {
                // Prepare place for a new element
                element = _element_to_add();
                if (element) {
                    // Read file to buffer
                    res = _read_file(file_name, element);
                }
            }
        }
    }
    _safe_mutex_unlock(&_lock);

    return res;
}

/******************************************************************************/
ssize_t
vs_file_cache_get_len(const char *file_name) {
    vs_file_cache_element_t *element;
    ssize_t res = -1;
    _safe_mutex_lock(&_lock);
    {
        if (_ctx.enabled) {
            element = _find_element(file_name);
            if (element) {
                res = element->file_sz;
            }
        }
    }
    _safe_mutex_unlock(&_lock);
    return res;
}

/******************************************************************************/
int
vs_file_cache_read(const char *file_name, uint32_t offset, uint8_t *data, size_t buf_sz, size_t *read_sz) {
    vs_file_cache_element_t *element;
    size_t max_avail_sz;
    int res = -1;

    assert(read_sz);
    assert(data);
    if (!read_sz || !data) {
        return -1;
    }

    _safe_mutex_lock(&_lock);
    {
        if (_ctx.enabled) {
            element = _find_element(file_name);
            if (element && element->file_sz > offset) {
                max_avail_sz = element->file_sz - offset;
                *read_sz = max_avail_sz < buf_sz ? max_avail_sz : buf_sz;
                memcpy(data, &element->data[offset], *read_sz);
                res = 0;
            }
        }
    }
    _safe_mutex_unlock(&_lock);
    return res;
}

/******************************************************************************/
int
vs_file_cache_write(const char *file_name, uint32_t offset, const uint8_t *data, size_t data_sz) {
    vs_file_cache_element_t *element;
    int res = -1;

    assert(data);
    assert(offset + data_sz <= UINT32_MAX);
    if (!data || (offset + data_sz > UINT32_MAX)) {
        return -1;
    }

    _safe_mutex_lock(&_lock);
    {
        if (_ctx.enabled) {
            element = _find_element(file_name);

            if (element) {
                if (element->file_sz < offset + data_sz) {
                    uint8_t *ptr = realloc(element->data, offset + data_sz);
                    if (!ptr) {
                        goto terminate;
                    }

                    if (element->file_sz && element->file_sz < offset) {
                        memset(&ptr[element->file_sz - 1], 0xFF, offset - element->file_sz);
                    }

                    element->data = ptr;
                    element->file_sz = offset + data_sz;
                    element->last_usage_time = time(NULL);
                }
                memcpy(&element->data[offset], data, data_sz);
                res = 0;
            }
        }
    }
terminate:
    _safe_mutex_unlock(&_lock);
    return res;
}

/******************************************************************************/
int
vs_file_cache_create(const char *file_name, const uint8_t *data, size_t data_sz) {
    vs_file_cache_element_t *element = NULL;
    int res = -1;

    assert(data);
    assert(data_sz);
    if (!data || 0 == data_sz || data_sz >= VS_FILE_CACHE_MAX_FILE_SZ) {
        return -1;
    }

    _safe_mutex_lock(&_lock);
    {
        if (_ctx.enabled) {
            element = _find_element(file_name);
            if (element) {
                _free_element(element);
            }
            // Prepare place for a new element
            element = _element_to_add();
            if (element) {
                element->last_usage_time = time(NULL);
                element->fn = strdup(file_name);
                element->file_sz = data_sz;

                element->data = malloc(element->file_sz);

                if (!element->data) {
                    goto terminate;
                }

                memcpy(element->data, data, data_sz);
                res = 0;
            }
        }
    }
terminate:
    if (0 != res && element) {
        _free_element(element);
    }

    _safe_mutex_unlock(&_lock);

    return res;
}

/******************************************************************************/
bool
vs_file_cache_is_enabled() {
    bool res;
    _safe_mutex_lock(&_lock);
    { res = _ctx.enabled; }
    _safe_mutex_unlock(&_lock);
    return res;
}
/******************************************************************************/
int
vs_file_cache_sync(const char *file_name) {
    FILE *fp = NULL;
    int res = -1;
    vs_file_cache_element_t *element;

    _safe_mutex_lock(&_lock);
    {
        if (_ctx.enabled) {
            element = _find_element(file_name);
            if (element) {
                fp = fopen(file_name, "wb");
                if (fp) {
                    if (1 == fwrite(element->data, element->file_sz, 1, fp)) {
                        res = 0;
                    } else {
                        printf("Can't write file\n");
                    }
                    fclose(fp);
                }
            }
        }
    }
    _safe_mutex_unlock(&_lock);
    return res;
}

/******************************************************************************/
void
vs_file_cache_close(const char *file_name) {
    _safe_mutex_lock(&_lock);
    _file_cache_close_internal(file_name);
    _safe_mutex_unlock(&_lock);
}

/******************************************************************************/
void
vs_file_cache_clean(void) {
    int i;
    _safe_mutex_lock(&_lock);
    {
        if (_ctx.enabled) {
            for (i = 0; i < VS_FILE_CACHE_SZ; i++) {
                _free_element(&_ctx.elements[i]);
            }
        }
        memset(&_ctx, 0, sizeof(_ctx));
    }
    _safe_mutex_unlock(&_lock);
}

/******************************************************************************/
