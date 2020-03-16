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

#include <stdbool.h>
#include <stdint.h>

#include "threads/main-thread.h"
#include "threads/message-bin-thread.h"

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/firmware/firmware.h>
#include <private/cloud_include.h>

#define MB_QUEUE_SZ 10
#define MB_THREAD_STACK_SZ (16 * 1024)

static xQueueHandle upd_event_queue = 0;
static xTaskHandle _mb_thread;
static BaseType_t is_threads_started;

/*************************************************************************/
static void
_firmware_topic_process(const uint8_t *url, uint16_t length) {
#if 0
    device_t *device = vs_device_ctx();

    upd_request_t *fw_url = (upd_request_t *)pvPortMalloc(sizeof(upd_request_t));
    assert(NULL != fw_url);
    if (NULL == fw_url) {
        VS_LOG_ERROR("Can't allocate memory");
        return;
    }

    memset(fw_url->upd_file_url, 0, sizeof(fw_url->upd_file_url));
    memcpy(fw_url->upd_file_url, url, length);

    fw_url->upd_type = MSG_BIN_UPD_TYPE_FW;

    if (pdTRUE != xQueueSendToBack(upd_event_queue, &fw_url, OS_NO_WAIT)) {
        VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
    } else {
        xEventGroupSetBits(device->message_bin_events, MSG_BIN_RECEIVE_BIT);
        return;
    }

    vPortFree(fw_url);
#endif
}

/*************************************************************************/
static void
_tl_topic_process(const uint8_t *url, uint16_t length) {
    device_t *device = vs_device_ctx();
    upd_request_t *tl_url = (upd_request_t *)pvPortMalloc(sizeof(upd_request_t));
    assert(NULL != tl_url);
    if (NULL == tl_url) {
        VS_LOG_ERROR("Can't allocate memory");
        return;
    }
    memset(tl_url->upd_file_url, 0, sizeof(tl_url->upd_file_url));
    memcpy(tl_url->upd_file_url, url, length);

    tl_url->upd_type = MSG_BIN_UPD_TYPE_TL;

    if (pdTRUE != xQueueSendToBack(upd_event_queue, &tl_url, OS_NO_WAIT)) {
        VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
    } else {
        xEventGroupSetBits(device->message_bin_events, MSG_BIN_RECEIVE_BIT);
        return;
    }

    vPortFree(tl_url);
}

/*************************************************************************/
static void
_mb_mqtt_task(void *params) {
    vs_status_e res;

    VS_LOG_DEBUG("message bin thread started");

    while (true) {
        res = vs_cloud_message_bin_process();
        if (VS_CODE_OK == res) {
            vs_impl_msleep(500);
        } else {
            vs_impl_msleep(5000);
        }
    }

    vTaskDelete(NULL);
    return;
}

/*************************************************************************/
vs_status_e
vs_message_bin_register_handlers(void) {
    vs_status_e ret_code;
    STATUS_CHECK_RET(vs_cloud_message_bin_register_default_handler(VS_CLOUD_MB_TOPIC_TL, _tl_topic_process),
                     "Error register handler for TL topic");
    STATUS_CHECK_RET(vs_cloud_message_bin_register_default_handler(VS_CLOUD_MB_TOPIC_FW, _firmware_topic_process),
                     "Error register handler for FW topic");

    return VS_CODE_OK;
}

/*************************************************************************/
xTaskHandle *
vs_message_bin_start_thread() {

    if (pdFALSE == is_threads_started) {
        upd_event_queue = xQueueCreate(MB_QUEUE_SZ, sizeof(upd_request_t *));

        is_threads_started = xTaskCreate(_mb_mqtt_task, "_mb_mqtt_task", MB_THREAD_STACK_SZ, 0, OS_PRIO_3, &_mb_thread);

        if (pdFALSE == is_threads_started) {
            return NULL;
        }
    }
    return &_mb_thread;
}

/*************************************************************************/
bool
vs_message_bin_get_request(upd_request_t **request) {
    *request = NULL;

    if (upd_event_queue && uxQueueMessagesWaiting(upd_event_queue)) {
        if (pdTRUE == xQueueReceive(upd_event_queue, request, 0))
            return true;
    }

    return false;
}

/*************************************************************************/
