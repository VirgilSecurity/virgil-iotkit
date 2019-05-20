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

#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <virgil/iot/protocols/sdmp/PRVS.h>

// For the simplest implementation of os_event
static pthread_mutex_t _wait_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _wait_cond = PTHREAD_COND_INITIALIZER;

/******************************************************************************/
static int
vs_prvs_stop_wait_func(void) {
    pthread_mutex_lock(&_wait_mutex);
    pthread_cond_signal(&_wait_cond);
    pthread_mutex_unlock(&_wait_mutex);
    return 0;
}

/******************************************************************************/
static int
vs_prvs_wait_func(size_t wait_ms) {
    struct timespec time_to_wait;
    struct timeval now;

    gettimeofday(&now, NULL);

    time_to_wait.tv_sec = now.tv_sec + wait_ms / 1000UL;
    time_to_wait.tv_nsec = (now.tv_usec + 1000UL * (wait_ms % 1000)) * 1000UL;

    pthread_mutex_lock(&_wait_mutex);
    pthread_cond_timedwait(&_wait_cond, &_wait_mutex, &time_to_wait);
    pthread_mutex_unlock(&_wait_mutex);
    return 0;
}

/******************************************************************************/
vs_sdmp_prvs_impl_t
vs_prvs_impl() {
    vs_sdmp_prvs_impl_t res;

    memset(&res, 0, sizeof(res));

    res.stop_wait_func = vs_prvs_stop_wait_func;
    res.wait_func = vs_prvs_wait_func;

    return res;
}