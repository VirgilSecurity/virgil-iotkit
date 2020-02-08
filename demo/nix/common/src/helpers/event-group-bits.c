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

#include <errno.h>
#include <stdio.h>
#include <sys/time.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>

#include "helpers/event-group-bits.h"

/******************************************************************************/
vs_event_bits_t
vs_event_group_wait_bits(vs_event_group_bits_t *ev_group,
                         vs_event_bits_t bits_to_wait_for,
                         bool is_clear_on_exit,
                         bool is_wait_for_all,
                         int32_t timeout) {

    int res = 0;
    struct timeval now;
    struct timespec thread_sleep;
    vs_event_bits_t stat = 0;

    assert(ev_group);
    CHECK_NOT_ZERO_RET(ev_group, 0);

    gettimeofday(&now, 0);
    thread_sleep.tv_sec = now.tv_sec + timeout;
    thread_sleep.tv_nsec = now.tv_usec * 1000;

    if (0 != pthread_mutex_lock(&ev_group->mtx)) {
        assert(false);
        return 0;
    }

    stat = ev_group->event_flags & bits_to_wait_for;

    while ((is_wait_for_all ? 0 == stat : bits_to_wait_for != stat) && ETIMEDOUT != res) {
        if (timeout >= 0) {
            res = pthread_cond_timedwait(&ev_group->cond, &ev_group->mtx, &thread_sleep);
        } else {
            res = pthread_cond_wait(&ev_group->cond, &ev_group->mtx);
        }
        stat = ev_group->event_flags & bits_to_wait_for;
        CHECK_RET(ETIMEDOUT == res || 0 == res, 0, "Error while wait condition, %s (%d)\n", strerror(errno), errno);
    }


    if (is_clear_on_exit) {
        ev_group->event_flags &= ~bits_to_wait_for;
    }

    if (0 != pthread_mutex_unlock(&ev_group->mtx)) {
        VS_LOG_ERROR("pthread_mutex_unlock. errno, %s (%d)", strerror(errno), errno);
    }
    return stat;
}

/******************************************************************************/
vs_event_bits_t
vs_event_group_clear_bits(vs_event_group_bits_t *ev_group, vs_event_bits_t bits_to_clear) {
    vs_event_bits_t stat = 0;
    assert(ev_group);
    CHECK_NOT_ZERO_RET(ev_group, 0);

    if (0 != pthread_mutex_lock(&ev_group->mtx)) {
        assert(false);
        return 0;
    }

    stat = ev_group->event_flags;
    ev_group->event_flags &= ~bits_to_clear;

    if (0 != pthread_mutex_unlock(&ev_group->mtx)) {
        VS_LOG_ERROR("pthread_mutex_unlock. errno, %s (%d)", strerror(errno), errno);
    }

    return stat;
}

/******************************************************************************/
vs_event_bits_t
vs_event_group_set_bits(vs_event_group_bits_t *ev_group, vs_event_bits_t bits_to_set) {
    vs_event_bits_t stat = 0;
    assert(ev_group);
    CHECK_NOT_ZERO_RET(ev_group, 0);

    if (0 != pthread_mutex_lock(&ev_group->mtx)) {
        assert(false);
        return 0;
    }

    stat = ev_group->event_flags;
    ev_group->event_flags |= bits_to_set;

    if (0 != pthread_mutex_unlock(&ev_group->mtx)) {
        VS_LOG_ERROR("pthread_mutex_unlock. errno, %s (%d)", strerror(errno), errno);
        return stat;
    }

    if (0 != pthread_cond_broadcast(&ev_group->cond)) {
        VS_LOG_ERROR("pthread_cond_broadcast. errno, %s (%d)", strerror(errno), errno);
    }

    return stat;
}

/******************************************************************************/
int
vs_event_group_init(vs_event_group_bits_t *ev_group) {
    assert(ev_group);
    CHECK_NOT_ZERO_RET(ev_group, -1);

    ev_group->event_flags = 0;

    if (0 != pthread_cond_init(&ev_group->cond, NULL)) {
        VS_LOG_ERROR("Error init condition var %s (%d)", strerror(errno), errno);
        return -1;
    }

    if (0 != pthread_mutex_init(&ev_group->mtx, NULL)) {
        VS_LOG_ERROR("Error init mutex var %s (%d)", strerror(errno), errno);
        return -1;
    }
    return 0;
}

/******************************************************************************/
int
vs_event_group_destroy(vs_event_group_bits_t *ev_group) {
    assert(ev_group);
    CHECK_NOT_ZERO_RET(ev_group, -1);
    pthread_cond_destroy(&ev_group->cond);
    pthread_mutex_destroy(&ev_group->mtx);
    return 0;
}

/******************************************************************************/
