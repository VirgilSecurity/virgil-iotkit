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

#include "threads/msgr-thread.h"
#include "threads/main-thread.h"
#include "event-flags.h"

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/messenger/messenger.h>
#include "helpers/msg-queue.h"

static pthread_t msgr_thread;
static vs_msg_queue_ctx_t *_event_queue;

static bool is_msgr_started;

#define MSGR_QUEUE_SZ 10

/*************************************************************************/
static void *
_msgr_task(void *pvParameters) {
    gtwy_t *gtwy = vs_gateway_ctx();
    vs_log_thread_descriptor("msgr thr");

    // Wait for the snap stack and services to be up before looking for messages
    vs_event_group_wait_bits(&gtwy->shared_events, SNAP_INIT_FINITE_BIT, false, true, VS_EVENT_GROUP_WAIT_INFINITE);

    VS_LOG_DEBUG("msgr thread started");

    while (1) {
        const void *info = NULL;
        const uint8_t *data = NULL;
        size_t data_sz = 0;

        if (VS_CODE_OK == vs_msg_queue_pop(_event_queue, &info, &data, &data_sz)) {
            if (data_sz) {
                vs_messenger_send(vs_messenger_default_channel(), (char *)data);
            } else {
                VS_LOG_DEBUG("MSGR device sent an empty data");
            }
            free((void *)data);
        } else {
            VS_LOG_ERROR("Error read from msgr queue");
            vs_impl_msleep(1000);
        }
    }
    return NULL;
}

/*************************************************************************/
pthread_t *
vs_msgr_start_thread(void) {
    if (!is_msgr_started) {

        _event_queue = vs_msg_queue_init(MSGR_QUEUE_SZ, 1, 1);

        is_msgr_started = (0 == pthread_create(&msgr_thread, NULL, _msgr_task, NULL));
        if (!is_msgr_started) {
            return NULL;
        }
    }
    return &msgr_thread;
}

/*************************************************************************/
bool
vs_msgr_send_message_to_messenger(uint8_t *data, uint32_t data_sz) {
    CHECK_NOT_ZERO_RET(_event_queue, false);
    CHECK_RET(VS_CODE_OK == vs_msg_queue_push(_event_queue, NULL, data, data_sz),
              false,
              "[MB] Failed to send msgr data to output processing!!!");
    return true;
}