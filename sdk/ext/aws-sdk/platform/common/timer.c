/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/**
 * @file timer.c
 * @brief Linux implementation of the timer interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "timer_platform.h"

bool
has_timer_expired(Timer *timer) {
#ifndef WIN32
    struct timeval now, res;
    gettimeofday(&now, NULL);
    timersub(&timer->end_time, &now, &res);
    return res.tv_sec < 0 || (res.tv_sec == 0 && res.tv_usec <= 0);
#else 
return false;   
#endif
}

void
countdown_ms(Timer *timer, uint32_t timeout) {
#ifndef WIN32
    struct timeval now;
#ifdef __cplusplus
    struct timeval interval = {timeout / 1000, static_cast<int>((timeout % 1000) * 1000)};
#else
    struct timeval interval = {timeout / 1000, (int)((timeout % 1000) * 1000)};
#endif
    gettimeofday(&now, NULL);
    timeradd(&now, &interval, &timer->end_time);
#endif    
}

uint32_t
left_ms(Timer *timer) {
#ifndef WIN32
    struct timeval now, res;
    uint32_t result_ms = 0;
    gettimeofday(&now, NULL);
    timersub(&timer->end_time, &now, &res);
    if (res.tv_sec >= 0) {
        result_ms = (uint32_t)(res.tv_sec * 1000 + res.tv_usec / 1000);
    }
    return result_ms;
#else    
return 0;   
#endif    
}

void
countdown_sec(Timer *timer, uint32_t timeout) {
#ifndef WIN32
    struct timeval now;
    struct timeval interval = {timeout, 0};
    gettimeofday(&now, NULL);
    timeradd(&now, &interval, &timer->end_time);
#endif    
}

void
init_timer(Timer *timer) {
#ifndef WIN32
    timer->end_time = (struct timeval){0, 0};
#endif    
}

void
delay(unsigned milliseconds) {
#ifndef WIN32
    useconds_t sleepTime = (useconds_t)(milliseconds * 1000);

    usleep(sleepTime);
#endif    
}

#ifdef __cplusplus
}
#endif
