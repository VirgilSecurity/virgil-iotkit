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

#ifndef GATEWAY_H
#define GATEWAY_H

#include <stdint.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/provision/provision-structs.h>
#include <global-hal.h>

/* OS priorities */
#define OS_PRIO_0 4 /** High **/
#define OS_PRIO_1 3
#define OS_PRIO_2 2
#define OS_PRIO_3 1
#define OS_PRIO_4 0 /** Low **/

/** Wait Forever */
#define OS_WAIT_FOREVER portMAX_DELAY
/** Do Not Wait */
#define OS_NO_WAIT 0

#define EVENT_BIT(NUM) ((EventBits_t)1 << (EventBits_t)NUM)

// Shared flags (shared_events)
#define SNAP_INIT_FINITE_BIT EVENT_BIT(0)
#define WIFI_INIT_BIT EVENT_BIT(1)

// Firmware upgrade flags (message_bin)
#define NEW_FIRMWARE_HTTP_BIT EVENT_BIT(0)
#define NEW_FW_URL EVENT_BIT(1)
#define MSG_BIN_RECEIVE_BIT EVENT_BIT(2)

typedef struct device_s {
    uint8_t *manufacture_id;
    uint8_t *device_type;

    EventGroupHandle_t shared_events;
    EventGroupHandle_t message_bin_events;

    SemaphoreHandle_t firmware_mutex;
    SemaphoreHandle_t tl_mutex;
} device_t;

device_t *
vs_device_ctx_init(uint8_t *manufacture_id, uint8_t *device_type);

device_t *
vs_device_ctx(void);

void
vs_main_start_threads(void);

#endif // GATEWAY_H
