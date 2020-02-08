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

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "helpers/msg-queue.h"
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/status_code/status_code.h>

typedef struct {
    const void *info;
    const uint8_t *data;
    size_t size;
} vs_queue_data_t;

struct vs_msg_queue_ctx_s {
    vs_queue_data_t **queue;
    int32_t mem;
    int32_t head;
    int32_t tail;
    int32_t n;
    int32_t length;
    int64_t id;
    int32_t num_adders;
    int32_t num_getters;
    pthread_mutex_t *mut;
    pthread_cond_t *not_full;
    pthread_cond_t *not_empty;
    pthread_cond_t *is_empty;
    pthread_cond_t *not_flush;
    int8_t state;
#ifdef QUEUE_DEBUG
    int32_t num_waiting[4];
#endif
};

enum { QUEUE_STATE_OK = 0, QUEUE_STATE_EOF = 1, QUEUE_STATE_FLUSH = 2 };
typedef void (*vs_queue_data_free_cb_t)();
static void
_data_destroyer(vs_queue_data_t *queue_data);

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
_queue_close_nolock(vs_msg_queue_ctx_t *q) {
    if (QUEUE_STATE_EOF == q->state)
        return;
    q->state = QUEUE_STATE_EOF;
    pthread_cond_broadcast(q->not_full);
    pthread_cond_broadcast(q->not_empty);
}

/******************************************************************************/
static void
_queue_signal(vs_msg_queue_ctx_t *q) {
    if (q->n < q->mem)
        pthread_cond_signal(q->not_full);
    if (0 == q->n)
        pthread_cond_signal(q->is_empty);
    if (0 < q->n)
        pthread_cond_signal(q->not_empty);
}

/******************************************************************************/
static vs_msg_queue_ctx_t *
_queue_init(int32_t capacity, int32_t num_adders, int32_t num_getters) {
    vs_msg_queue_ctx_t *q = calloc(1, sizeof(vs_msg_queue_ctx_t));
    CHECK(NULL != q, "Can't allocate memory");

    q->mem = capacity;
    q->queue = calloc(q->mem, sizeof(vs_queue_data_t *));
    CHECK(NULL != q->queue, "Can't allocate memory");

    q->mut = calloc(1, sizeof(pthread_mutex_t));
    CHECK(NULL != q->mut, "Can't allocate memory");
    q->not_full = calloc(1, sizeof(pthread_cond_t));
    CHECK(NULL != q->not_full, "Can't allocate memory");
    q->not_empty = calloc(1, sizeof(pthread_cond_t));
    CHECK(NULL != q->not_empty, "Can't allocate memory");
    q->is_empty = calloc(1, sizeof(pthread_cond_t));
    CHECK(NULL != q->is_empty, "Can't allocate memory");
    q->not_flush = calloc(1, sizeof(pthread_cond_t));
    CHECK(NULL != q->not_flush, "Can't allocate memory");
    q->state = QUEUE_STATE_OK;
    q->num_adders = num_adders;
    q->num_getters = num_getters;
#ifdef QUEUE_DEBUG
    q->num_waiting[0] = 0;
    q->num_waiting[1] = 0;
    q->num_waiting[2] = 0;
    q->num_waiting[3] = 0;
#endif

    if (0 != pthread_mutex_init(q->mut, NULL)) {
        fprintf(stderr, "Could not create mutex\n");
        exit(1);
    }
    if (0 != pthread_cond_init(q->not_full, NULL)) {
        fprintf(stderr, "Could not create condition\n");
        exit(1);
    }
    if (0 != pthread_cond_init(q->not_empty, NULL)) {
        fprintf(stderr, "Could not create condition\n");
        exit(1);
    }
    if (0 != pthread_cond_init(q->is_empty, NULL)) {
        fprintf(stderr, "Could not create condition\n");
        exit(1);
    }
    if (0 != pthread_cond_init(q->not_flush, NULL)) {
        fprintf(stderr, "Could not create condition\n");
        exit(1);
    }

    return q;
terminate:
    exit(1);
}

/******************************************************************************/
static int8_t
_queue_add(vs_msg_queue_ctx_t *q, vs_queue_data_t *b, int8_t wait) {
    _safe_mutex_lock(q->mut);
    _queue_signal(q);
    if (0 == q->num_getters) {  // no more getters
        _queue_close_nolock(q); // close
        _safe_mutex_unlock(q->mut);
        return 0;
    } else if (0 == q->num_adders) { // then why are you adding?
        _queue_close_nolock(q);
        _safe_mutex_unlock(q->mut);
        return 0;
    }
    while (q->n == q->mem) {
        if (wait && QUEUE_STATE_OK == q->state) {
#ifdef QUEUE_DEBUG
            q->num_waiting[0]++;
#endif
            if (0 != pthread_cond_wait(q->not_full, q->mut)) {
                fprintf(stderr, "Could not condition wait\n");
                exit(1);
            }
#ifdef QUEUE_DEBUG
            q->num_waiting[0]--;
#endif
        } else {
            if (0 == q->num_getters)
                _queue_close_nolock(q);
            _queue_signal(q);
            _safe_mutex_unlock(q->mut);
            return 0;
        }
    }
    q->id++;
    q->queue[q->tail++] = b;
    if (q->tail == q->mem)
        q->tail = 0;

    q->n++;
    _queue_signal(q);
    _safe_mutex_unlock(q->mut);
    return 1;
}

/******************************************************************************/
static vs_queue_data_t *
_queue_get(vs_msg_queue_ctx_t *q, int8_t wait) {
    vs_queue_data_t *b = NULL;
    _safe_mutex_lock(q->mut);
    _queue_signal(q);
    if (0 == q->num_getters) {  // then why are you getting
        _queue_close_nolock(q); // close the queue
        _safe_mutex_unlock(q->mut);
        return NULL;
    } else if (0 == q->n && 0 == q->num_adders) {
        _queue_close_nolock(q);
        _safe_mutex_unlock(q->mut);
        return NULL;
    }
    while (0 == q->n) {
        if (1 == wait && QUEUE_STATE_OK == q->state) {
#ifdef QUEUE_DEBUG
            q->num_waiting[2]++;
#endif
            if (0 != pthread_cond_wait(q->not_empty, q->mut)) {
                fprintf(stderr, "Could not condition wait\n");
                exit(1);
            }
#ifdef QUEUE_DEBUG
            q->num_waiting[2]--;
#endif
        } else {
            if (0 == q->num_adders)
                _queue_close_nolock(q); // close the queue
            _queue_signal(q);
            _safe_mutex_unlock(q->mut);
            return NULL;
        }
    }
    b = q->queue[q->head];
    q->queue[q->head++] = NULL;
    if (q->head == q->mem)
        q->head = 0;
    q->n--;
    _queue_signal(q);
    _safe_mutex_unlock(q->mut);
    return b;
}

/******************************************************************************/
static void
_queue_close(vs_msg_queue_ctx_t *q) {
    if (QUEUE_STATE_EOF == q->state)
        return;
    _safe_mutex_lock(q->mut);
    _queue_close_nolock(q);
    _safe_mutex_unlock(q->mut);
}

/******************************************************************************/
static void
_queue_reset(vs_msg_queue_ctx_t *q, int32_t num_adders, int32_t num_getters) {
    int32_t i;
    _safe_mutex_lock(q->mut);
    for (i = 0; i < q->mem; i++) {
        if (NULL != q->queue[i]) {
            _data_destroyer(q->queue[i]);
            q->queue[i] = NULL;
        }
    }
    q->head = q->tail = q->n = 0;
    q->id = 0;
    q->state = QUEUE_STATE_OK;
    q->num_adders = num_adders;
    q->num_getters = num_getters;
    _safe_mutex_unlock(q->mut);
}

/******************************************************************************/
static void
_queue_destroy(vs_msg_queue_ctx_t *q) {
    int32_t i;
    if (NULL == q)
        return;
    _queue_close(q);
    for (i = 0; i < q->mem; i++) {
        _data_destroyer(q->queue[i]);
    }
    free(q->queue);
    free(q->mut);
    free(q->not_full);
    free(q->not_empty);
    free(q->is_empty);
    free(q->not_flush);
    free(q);
}

/******************************************************************************/
#ifdef QUEUE_DEBUG
static void
queue_print_status(vs_msg_queue_ctx_t *q, FILE *fp) {
    fprintf(fp, "QUEUE STATUS\n");
    fprintf(fp,
            "mem=%d head=%d tail=%d n=%d length=%d id=%lld num_adders=%d num_getters=%d\n",
            q->mem,
            q->head,
            q->tail,
            q->n,
            q->length,
            q->id,
            q->num_adders,
            q->num_getters);
    fprintf(fp,
            "num_waiting=[%d,%d,%d,%d]\n",
            q->num_waiting[0],
            q->num_waiting[1],
            q->num_waiting[2],
            q->num_waiting[3]);
}
#endif
/******************************************************************************/
static void
_data_destroyer(vs_queue_data_t *queue_data) {
    if (queue_data) {
        if (queue_data->data) {
            free((void *)queue_data->data);
        }
        free(queue_data);
    }
}
/******************************************************************************/
vs_msg_queue_ctx_t *
vs_msg_queue_init(size_t queue_sz, size_t num_adders, size_t num_getters) {
    return _queue_init(queue_sz, num_adders, num_getters);
}

/******************************************************************************/
vs_status_e
vs_msg_queue_push(vs_msg_queue_ctx_t *ctx, const void *info, const uint8_t *data, size_t data_sz) {
    vs_queue_data_t *queue_data;
    int8_t res;
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Allocate structure
    queue_data = malloc(sizeof(vs_queue_data_t));
    if (!queue_data) {
        return VS_CODE_ERR_NO_MEMORY;
    }

    // Allocate and copy data
    if (data && data_sz) {
        queue_data->data = malloc(data_sz);
        if (!queue_data->data) {
            free(queue_data);
            return VS_CODE_ERR_NO_MEMORY;
        }
        memcpy((void *)queue_data->data, data, data_sz);
        queue_data->size = data_sz;
    } else {
        memset(queue_data, 0, sizeof(*queue_data));
    }
    queue_data->info = info;

    // Add to Queue
    res = _queue_add(ctx, queue_data, true);
    if (1 != res) {
        // error add to queue
        if (data && data_sz) {
            free((void *)queue_data->data);
        }

        free(queue_data);
        return VS_CODE_ERR_NO_MEMORY;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_msg_queue_pop(vs_msg_queue_ctx_t *ctx, const void **info, const uint8_t **data, size_t *data_sz) {
    vs_queue_data_t *queue_data;
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(info, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    queue_data = _queue_get(ctx, true);

    if (!queue_data) {
        return VS_CODE_ERR_INCORRECT_PARAMETER;
    }

    *info = queue_data->info;
    *data = queue_data->data;
    *data_sz = queue_data->size;

    free(queue_data);

    return VS_CODE_OK;
}

/******************************************************************************/
bool
vs_msg_queue_data_present(vs_msg_queue_ctx_t *ctx) {
    CHECK_NOT_ZERO_RET(ctx, false);
    bool is_present;
    _safe_mutex_lock(ctx->mut);
    is_present = ctx->n;
    _safe_mutex_unlock(ctx->mut);

    return is_present;
}

/******************************************************************************/
void
vs_msg_queue_reset(vs_msg_queue_ctx_t *ctx) {
    if (ctx) {
        _queue_reset(ctx, ctx->num_adders, ctx->num_getters);
    }
}

/******************************************************************************/
void
vs_msg_queue_free(vs_msg_queue_ctx_t *ctx) {
    if (ctx) {
        _queue_destroy(ctx);
    }
}

/******************************************************************************/
