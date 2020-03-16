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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "threads/main-thread.h"
#include "threads/message-bin-thread.h"
#include "threads/file-download-thread.h"

#include <global-hal.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/protocols/snap/fldt/fldt-server.h>
#include <virgil/iot/trust_list/trust_list.h>

#define MAIN_THREAD_SLEEP_MS (2000)

static device_t _device;

#if SIMULATOR
static const char _test_message[] = TEST_UPDATE_MESSAGE;
#endif

static xTaskHandle *message_bin_thread;
static xTaskHandle *upd_http_retrieval_thread;

/******************************************************************************/
device_t *
vs_device_ctx_init(uint8_t *manufacture_id, uint8_t *device_type) {
    _device.manufacture_id = manufacture_id;
    _device.device_type = device_type;

    _device.message_bin_events = xEventGroupCreate();
    _device.shared_events = xEventGroupCreate();

    _device.firmware_mutex = xSemaphoreCreateMutex();
    _device.tl_mutex = xSemaphoreCreateMutex();

    return &_device;
}

/******************************************************************************/
device_t *
vs_device_ctx(void) {
    return &_device;
}

/*************************************************************************/
static bool
_is_self_firmware_image(vs_file_info_t *fw_info) {
    vs_firmware_descriptor_t desc;
    STATUS_CHECK_RET_BOOL(vs_firmware_get_own_firmware_descriptor(&desc), "Unable to get own firmware descriptor");

    return (0 == memcmp(desc.info.manufacture_id, fw_info->manufacture_id, VS_DEVICE_MANUFACTURE_ID_SIZE) &&
            0 == memcmp(desc.info.device_type, fw_info->device_type, VS_DEVICE_TYPE_SIZE));
}

/*************************************************************************/
void
_stop_all_threads(void) {
    // Stop message bin thread
    vTaskDelete(*message_bin_thread);
    VS_LOG_INFO("message_bin_thread thread canceled");

    // Stop retrieval thread
    vTaskDelete(*upd_http_retrieval_thread);
    VS_LOG_INFO("upd_http_retrieval_thread thread canceled");

    /* Cleanup a mutexes */
    vSemaphoreDelete(_device.firmware_mutex);
    vSemaphoreDelete(_device.tl_mutex);

    vEventGroupDelete(_device.shared_events);
    vEventGroupDelete(_device.message_bin_events);
}

/*************************************************************************/
static void
_restart_app() {
    _stop_all_threads();

    // TODO: Need to restart app
    // vs_app_restart();

    // pthread_exit(0);
    VS_LOG_DEBUG("Reboot...");
    while (1) {
        vTaskDelay(30000 / portTICK_PERIOD_MS);
    };
}

/******************************************************************************/
void
vs_main_start_threads(void) {
    vs_firmware_descriptor_t desc;
    vs_update_file_type_t *queued_file;
    vs_file_info_t *request;

    // Start Message Bin processing thread
    message_bin_thread = vs_message_bin_start_thread();
    CHECK_NOT_ZERO(message_bin_thread);

    // Start files receive thread
    upd_http_retrieval_thread = vs_file_download_start_thread();
    CHECK_NOT_ZERO(upd_http_retrieval_thread);

    xEventGroupSetBits(_device.shared_events, SNAP_INIT_FINITE_BIT);

    // Main cycle
    while (1) {
#if SIMULATOR
        if (_test_message[0] != 0) { //-V547
            VS_LOG_INFO(_test_message);
        }
#endif
        vTaskDelay(MAIN_THREAD_SLEEP_MS / portTICK_PERIOD_MS);

        while (vs_file_download_get_request(&queued_file)) {

            switch (queued_file->type) {
            case VS_UPDATE_FIRMWARE:
                request = &queued_file->info;
                if (_is_self_firmware_image(request)) {
                    while (xSemaphoreTake(_device.firmware_mutex, portMAX_DELAY) == pdFALSE) {
                    }

                    if (VS_CODE_OK == vs_firmware_load_firmware_descriptor(
                                              request->manufacture_id, request->device_type, &desc) &&
                        VS_CODE_OK == vs_firmware_install_firmware(&desc)) {
                        (void)xSemaphoreGive(_device.firmware_mutex);

                        _restart_app();
                    }
                    (void)xSemaphoreGive(_device.firmware_mutex);
                }

                VS_LOG_DEBUG("Send info about new Firmware over SNAP");
#if 0
                if (vs_fldt_server_add_file_type(queued_file, vs_firmware_update_ctx(), true)) {
                    VS_LOG_ERROR("Unable to add new firmware");
                }
#endif
                break;

            case VS_UPDATE_TRUST_LIST:
                VS_LOG_DEBUG("Send info about new Trust List over SNAP");
#if 0
                if (vs_fldt_server_add_file_type(queued_file, vs_tl_update_ctx(), true)) {
                    VS_LOG_ERROR("Unable to add new Trust List");
                }
#endif
                break;

            default:
                VS_LOG_ERROR("Unsupported file type %d", queued_file->type);
                break;
            }

            vPortFree(queued_file);
        }
    }

terminate:
    VS_LOG_ERROR("Error during initialization workers");
    return;
}

/******************************************************************************/
