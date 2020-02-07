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
#include <errno.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <virgil/iot/tools/helpers/ti_wait_functionality.h>
#include <virgil/iot/logger/logger.h>

// For the simplest implementation of os_event
static pthread_mutex_t _wait_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _wait_cond = PTHREAD_COND_INITIALIZER;

/******************************************************************************/
vs_status_e
vs_wait_stop_func(int *condition, int expect) {
    if (0 != pthread_mutex_lock(&_wait_mutex)) {
        VS_LOG_ERROR("pthread_mutex_lock %s %d", strerror(errno), errno);
    }

    *condition = expect;

    if (0 != pthread_cond_broadcast(&_wait_cond)) {
        VS_LOG_ERROR("pthread_cond_signal %s\n", strerror(errno));
    }

    if (0 != pthread_mutex_unlock(&_wait_mutex)) {
        VS_LOG_ERROR("pthread_mutex_unlock %s\n", strerror(errno));
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static bool
_is_greater_timespec(struct timespec a, struct timespec b) {
    if (a.tv_sec == b.tv_sec) {
        return a.tv_nsec > b.tv_nsec;
    }

    return a.tv_sec > b.tv_sec;
}

/******************************************************************************/
vs_status_e
vs_wait_func(uint32_t wait_ms, int *condition, int idle) {
    struct timespec time_to_wait;
    struct timespec ts_now;

    // Check for expected condition
    if (*condition != idle) {
        return 0;
    }

    // Wait for expected condition
    clock_gettime(CLOCK_REALTIME, &ts_now);
    time_to_wait.tv_sec = ts_now.tv_sec + wait_ms / 1000UL;
    time_to_wait.tv_nsec = ts_now.tv_nsec + 1000000UL * (wait_ms % 1000UL);

    if (0 != pthread_mutex_lock(&_wait_mutex)) {
        VS_LOG_ERROR("pthread_mutex_lock %s\n", strerror(errno));
    }

    do {
        pthread_cond_timedwait(&_wait_cond, &_wait_mutex, &time_to_wait);
        clock_gettime(CLOCK_REALTIME, &ts_now);
    } while (*condition == idle && !_is_greater_timespec(ts_now, time_to_wait));

    pthread_mutex_unlock(&_wait_mutex);

    return VS_CODE_OK;
}

/******************************************************************************/