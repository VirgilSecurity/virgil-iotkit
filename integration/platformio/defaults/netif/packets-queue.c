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

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include <defaults/netif/packets-queue.h>

#define VS_NETIF_QUEUE_SZ (100)

static vs_netif_process_cb_t _netif_process_cb = 0;
static bool _active_heart_beat = false;
static xQueueHandle _queue = NULL;

#define WAIT_MS (100 / portTICK_RATE_MS)

typedef struct {
    vs_netif_t *netif;
    uint8_t *data;
    size_t data_sz;
} vs_queue_packet;

/******************************************************************************/
static void
_queue_thread(void *pvParameters) {

    vs_queue_packet packet;

    while (1) {
        memset(&packet, 0, sizeof(packet));
        if (pdPASS != xQueueReceive(_queue, &packet, WAIT_MS)) {
            continue;
        }

        if (_netif_process_cb) {
            _netif_process_cb(packet.netif, packet.data, packet.data_sz);
        }

        if (packet.data) {
            vPortFree(packet.data);
        }
    }

    vTaskDelete(NULL);
}

/******************************************************************************/
static void
_heart_beat_task(void *pvParameters) {
    static const vs_queue_packet heart_beat_packet = {NULL, NULL, 0};
    while (1) {
        if (_active_heart_beat) {
            xQueueSendToBack(_queue, &heart_beat_packet, 0);
        }
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    vTaskDelete(NULL);
}

/******************************************************************************/
vs_status_e
vs_packets_queue_init(vs_netif_process_cb_t packet_processor) {
    // Save Callback function
    _netif_process_cb = packet_processor;

    // Initialize RX Queue
    _queue = xQueueCreate(5, sizeof(vs_queue_packet));
    CHECK_RET(_queue, VS_CODE_ERR_QUEUE, "Cannot create message queue.");

    // Start heart beat thread
    CHECK_RET(pdPASS == xTaskCreate(_heart_beat_task, "_heart_beat_task", 4096, NULL, 5, NULL),
              VS_CODE_ERR_THREAD,
              "Cannot start heart beat thread");

    // Start packets processing thread
    CHECK_RET(pdPASS == xTaskCreate(_queue_thread, "_queue_thread", 4 * 4096, NULL, 5, NULL),
              VS_CODE_ERR_THREAD,
              "Cannot start packets processing thread");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_packets_queue_deinit(void) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
vs_status_e
vs_packets_queue_add(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    vs_queue_packet packet;

    assert(_queue);
    assert(data);
    assert(data_sz);
    CHECK_RET(_queue, VS_CODE_ERR_NULLPTR_ARGUMENT, "Queue context is Wrong");

    packet.netif = netif;
    packet.data_sz = data_sz;
    packet.data = pvPortMalloc(data_sz);
    CHECK_RET(packet.data, VS_CODE_ERR_NO_MEMORY, "Cannot allocate memory for packet");

    memcpy(packet.data, data, data_sz);

    CHECK_RET(pdPASS == xQueueSendToBack(_queue, &packet, 0), VS_CODE_ERR_NO_MEMORY, "Cannot push packet to queue");

    return VS_CODE_OK;
}

/******************************************************************************/
void
vs_packets_queue_enable_heart_beat(bool enable) {
    _active_heart_beat = enable;
}

/******************************************************************************/
