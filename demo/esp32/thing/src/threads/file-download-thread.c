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

#include "threads/file-download-thread.h"
#include "threads/message-bin-thread.h"
#include "threads/main-thread.h"

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/trust_list/trust_list.h>

#define FWDIST_QUEUE_SZ 10
#define FILE_DOWNLOAD_THREAD_STACK_SZ (10 * 1024)


static xTaskHandle upd_retrieval_thread;
static xQueueHandle _event_queue = 0;

static BaseType_t is_retrieval_started;

// Wrapper to wait until event group bits are set and not timed out
/*************************************************************************/
static EventBits_t
_wait_indefinitely(EventGroupHandle_t xEventGroup,
                   const EventBits_t uxBitsToWaitFor,
                   const BaseType_t xClearOnExit,
                   BaseType_t xWaitForAllBits) {
    // Wait until the bits returned are the bits desired
    if (xWaitForAllBits) {
        while ((uxBitsToWaitFor &
                xEventGroupWaitBits(xEventGroup, uxBitsToWaitFor, pdFALSE, xWaitForAllBits, portMAX_DELAY)) !=
               uxBitsToWaitFor) {
        }
    } else {
        while ((uxBitsToWaitFor &
                xEventGroupWaitBits(xEventGroup, uxBitsToWaitFor, pdFALSE, xWaitForAllBits, portMAX_DELAY)) == 0) {
        }
    }
    EventBits_t setBits = xEventGroupGetBits(xEventGroup);

    // Clear since done waiting
    if (xClearOnExit) {
        xEventGroupClearBits(xEventGroup, uxBitsToWaitFor);
    }

    return setBits;
}

/*************************************************************************/
static void
_sw_retrieval_mb_notify(device_t *device, upd_request_t *request) {
    vs_firmware_header_t header;
    vs_update_file_type_t *fw_info = NULL;
    int res;

    // It should be immediately available given that this starts first
    while (xSemaphoreTake(device->firmware_mutex, portMAX_DELAY) == pdFALSE) {
    }


    VS_LOG_DEBUG("[MB_NOTIFY]:In while loop and got firmware semaphore");

    VS_LOG_DEBUG("[MB_NOTIFY]: Fetch new firmware from URL %s", request->upd_file_url);

    res = vs_cloud_fetch_and_store_fw_file(request->upd_file_url, &header);

    if (VS_CODE_OK == res) {
        VS_LOG_DEBUG("[MB_NOTIFY]:FW image stored successfully");

        res = vs_firmware_verify_firmware(&header.descriptor);
        if (VS_CODE_OK == res) {

            VS_LOG_DEBUG("[MB_NOTIFY]:FW Successful fetched");

            fw_info = calloc(1, sizeof(vs_update_file_type_t));
            if (!fw_info) {
                VS_LOG_ERROR("Can't allocate memory");
                return;
            }
            fw_info->type = VS_UPDATE_FIRMWARE;
            memcpy(&fw_info->info, &header.descriptor.info, sizeof(vs_file_info_t));

            if (pdTRUE != xQueueSendToBack(_event_queue, &fw_info, OS_NO_WAIT)) {
                free(fw_info);
                VS_LOG_ERROR("[MB] Failed to send fw info to output processing!!!");
            }

        } else {
            VS_LOG_DEBUG("[MB_NOTIFY]:Error verify firmware image\r\n");
            vs_firmware_delete_firmware(&header.descriptor);
        }

    } else {
        VS_LOG_DEBUG("[MB_NOTIFY]:Error fetch new firmware\r\n");
    }


    (void)xSemaphoreGive(device->firmware_mutex);
    VS_LOG_DEBUG("[MB_NOTIFY]:Firmware semaphore freed");

    // This thread needs to be signaled by the off chance that there was a powerloss
    xEventGroupSetBits(device->message_bin_events, NEW_FIRMWARE_HTTP_BIT);
    free(request);
}

/*************************************************************************/
static void
_tl_retrieval_mb_notify(device_t *device, upd_request_t *request) {
    vs_update_file_type_t *tl_info = NULL;
    vs_tl_element_info_t elem = {.id = VS_TL_ELEMENT_TLH};
    vs_tl_header_t tl_header;
    uint16_t tl_header_sz = sizeof(tl_header);
    int res;

    VS_LOG_DEBUG("[MB_NOTIFY]:In while loop and got TL semaphore\r\n");
    while (xSemaphoreTake(device->tl_mutex, portMAX_DELAY) == pdFALSE) {
    }

    res = vs_cloud_fetch_and_store_tl(request->upd_file_url);

    if (VS_CODE_OK == res) {
        VS_LOG_DEBUG("[MB_NOTIFY]:TL Successful fetched\r\n");

        CHECK(VS_CODE_OK == vs_tl_load_part(&elem, (uint8_t *)&tl_header, tl_header_sz, &tl_header_sz) &&
                      tl_header_sz == sizeof(tl_header),
              "Unable to load Trust List header");

        tl_info = calloc(1, sizeof(vs_update_file_type_t));
        if (!tl_info) {
            VS_LOG_ERROR("Can't allocate memory");
            exit(-1);
        }

        vs_tl_header_to_host(&tl_header, &tl_header);
        memset(tl_info, 0, sizeof(vs_update_file_type_t));
        memcpy(&tl_info->info.version, &tl_header.version, sizeof(vs_file_version_t));

        tl_info->type = VS_UPDATE_TRUST_LIST;

        if (pdTRUE != xQueueSendToBack(_event_queue, &tl_info, OS_NO_WAIT)) {
            free(tl_info);
            VS_LOG_ERROR("[MB] Failed to send TL info to output processing!!!");
        }

    } else {
        VS_LOG_DEBUG("[MB_NOTIFY]:Error fetch new TL\r\n");
    }

terminate:
    (void)xSemaphoreGive(device->tl_mutex);
    VS_LOG_DEBUG("[MB_NOTIFY]:TL semaphore freed\r\n");
    free(request);
}

/*************************************************************************/
static void
_upd_http_retrieval_task(void *pvParameters) {
    device_t *device = vs_device_ctx();

    // Wait for the snap stack and services to be up before looking for new firmware
    _wait_indefinitely(device->shared_events, SNAP_INIT_FINITE_BIT, false, true);

    VS_LOG_DEBUG("vs_upd_http_retrieval thread started");

    while (1) {
        upd_request_t *request = NULL;

        _wait_indefinitely(device->message_bin_events, MSG_BIN_RECEIVE_BIT, true, true);

        VS_LOG_DEBUG("vs_upd_http_retrieval thread resume");

        while (vs_message_bin_get_request(&request)) {
            if (!request)
                continue;
            if (MSG_BIN_UPD_TYPE_FW == request->upd_type) {
                _sw_retrieval_mb_notify(device, request);
            } else if (MSG_BIN_UPD_TYPE_TL == request->upd_type) {
                _tl_retrieval_mb_notify(device, request);
            } else {
                free(request);
            }
        }
    }

    vTaskDelete(NULL);
    return;
}

/*************************************************************************/
xTaskHandle *
vs_file_download_start_thread(void) {
    if (pdFALSE == is_retrieval_started) {
        _event_queue = xQueueCreate(FWDIST_QUEUE_SZ, sizeof(vs_update_file_type_t *));

        is_retrieval_started = xTaskCreate(_upd_http_retrieval_task,
                                           "sw-http-retrieval",
                                           FILE_DOWNLOAD_THREAD_STACK_SZ,
                                           0,
                                           OS_PRIO_3,
                                           &upd_retrieval_thread);

        if (pdFALSE == is_retrieval_started) {
            return NULL;
        }
    }
    return &upd_retrieval_thread;
}

/*************************************************************************/
bool
vs_file_download_get_request(vs_update_file_type_t **request) {
    *request = NULL;
    if (_event_queue && uxQueueMessagesWaiting(_event_queue)) {
        if (pdTRUE == xQueueReceive(_event_queue, request, 0)) {
            return true;
        }
    }

    return false;
}

/*************************************************************************/
