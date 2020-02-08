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

#ifndef VS_IOT_EVENT_GROUP_BITS_H
#define VS_IOT_EVENT_GROUP_BITS_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

typedef uint32_t vs_event_bits_t;
typedef struct vs_event_group_bits_s {
    pthread_cond_t cond;
    pthread_mutex_t mtx;
    vs_event_bits_t event_flags;
} vs_event_group_bits_t;

#define VS_EVENT_GROUP_WAIT_INFINITE (-1)
vs_event_bits_t
vs_event_group_wait_bits(vs_event_group_bits_t *ev_group,
                         vs_event_bits_t bits_to_wait_for,
                         bool is_clear_on_exit,
                         bool is_wait_for_all,
                         int32_t timeout);

vs_event_bits_t
vs_event_group_clear_bits(vs_event_group_bits_t *ev_group, vs_event_bits_t bits_to_clear);

vs_event_bits_t
vs_event_group_set_bits(vs_event_group_bits_t *ev_group, vs_event_bits_t bits_to_set);

int
vs_event_group_init(vs_event_group_bits_t *ev_group);

int
vs_event_group_destroy(vs_event_group_bits_t *ev_group);
#endif // VS_IOT_EVENT_GROUP_BITS_H
