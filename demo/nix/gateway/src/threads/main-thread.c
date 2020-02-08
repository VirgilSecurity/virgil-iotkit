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

#include "threads/main-thread.h"
#include "threads/message-bin-thread.h"
#include "threads/file-download-thread.h"
#include "event-flags.h"
#include "sdk-impl/storage/storage-nix-impl.h"
#include "helpers/app-helpers.h"

#include <global-hal.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/protocols/snap/fldt/fldt-server.h>
#include <virgil/iot/trust_list/trust_list.h>

static gtwy_t _gtwy = {.firmware_mutex = PTHREAD_MUTEX_INITIALIZER, .tl_mutex = PTHREAD_MUTEX_INITIALIZER};


static bool is_threads_started = false;
static pthread_t gateway_starter_thread;

#define MAIN_THREAD_SLEEP_S (2)

#if SIMULATOR
static const char _test_message[] = TEST_UPDATE_MESSAGE;
#endif

static pthread_t *message_bin_thread;
static pthread_t *upd_http_retrieval_thread;

/******************************************************************************/
gtwy_t *
vs_gateway_ctx_init(vs_mac_addr_t *mac_addr) {
    if (0 != vs_event_group_init(&_gtwy.incoming_data_events)) {
        exit(-1);
    }
    if (0 != vs_event_group_init(&_gtwy.message_bin_events)) {
        exit(-1);
    }
    if (0 != vs_event_group_init(&_gtwy.shared_events)) {
        exit(-1);
    }

    return &_gtwy;
}

/******************************************************************************/
gtwy_t *
vs_gateway_ctx(void) {
    return &_gtwy;
}

/*************************************************************************/
static bool
_is_self_firmware_image(vs_file_info_t *fw_info) {
    vs_firmware_descriptor_t desc;
    STATUS_CHECK_RET_BOOL(vs_firmware_get_own_firmware_descriptor(&desc), "Unable to get own firmware descriptor");

    return (0 == VS_IOT_MEMCMP(desc.info.manufacture_id, fw_info->manufacture_id, VS_DEVICE_MANUFACTURE_ID_SIZE) &&
            0 == VS_IOT_MEMCMP(desc.info.device_type, fw_info->device_type, VS_DEVICE_TYPE_SIZE));
}

/*************************************************************************/
static int
_cancel_thread(pthread_t *thread) {
    void *res;

    if (0 != pthread_cancel(*thread) || 0 != pthread_join(*thread, &res) || PTHREAD_CANCELED != res) {
        return -1;
    }

    return 0;
}

/*************************************************************************/
static void
_restart_app() {

    // Stop message bin thread
    if (0 != _cancel_thread(message_bin_thread)) {
        VS_LOG_ERROR("Unable to cancel message_bin_thread");
        exit(-1);
    }
    VS_LOG_INFO("message_bin_thread thread canceled");

    // Stop retrieval thread
    if (0 != _cancel_thread(upd_http_retrieval_thread)) {
        VS_LOG_ERROR("Unable to cancel upd_http_retrieval_thread");
        exit(-1);
    }
    VS_LOG_INFO("upd_http_retrieval_thread thread canceled");

    /* Cleanup a mutexes */
    pthread_mutex_destroy(&_gtwy.firmware_mutex);
    pthread_mutex_destroy(&_gtwy.tl_mutex);
    pthread_mutex_destroy(&_gtwy.shared_events.mtx);

    vs_event_group_destroy(&_gtwy.shared_events);
    vs_event_group_destroy(&_gtwy.incoming_data_events);
    vs_event_group_destroy(&_gtwy.message_bin_events);

    vs_app_restart();
    pthread_exit(0);
}

/******************************************************************************/
static void *
_gateway_task(void *pvParameters) {
    vs_firmware_descriptor_t desc;
    vs_update_file_type_t *queued_file;
    vs_file_info_t *request;

    vs_log_thread_descriptor("gtw thr");

    // Start Message Bin processing thread
    message_bin_thread = vs_message_bin_start_thread();
    CHECK_NOT_ZERO_RET(message_bin_thread, (void *)-1);

    // Start files receive thread
    upd_http_retrieval_thread = vs_file_download_start_thread();
    CHECK_NOT_ZERO_RET(upd_http_retrieval_thread, (void *)-1);

    // Main cycle
    while (true) {
        vs_event_group_wait_bits(&_gtwy.incoming_data_events, EID_BITS_ALL, true, false, MAIN_THREAD_SLEEP_S);
        vs_event_group_set_bits(&_gtwy.shared_events, SNAP_INIT_FINITE_BIT);

        while (vs_file_download_get_request(&queued_file)) {

            switch (queued_file->type) {
            case VS_UPDATE_FIRMWARE:
                request = &queued_file->info;
                if (_is_self_firmware_image(request)) {
                    if (0 == pthread_mutex_lock(&_gtwy.firmware_mutex)) {
                        if (VS_CODE_OK == vs_firmware_load_firmware_descriptor(
                                                  request->manufacture_id, request->device_type, &desc) &&
                            VS_CODE_OK == vs_firmware_install_firmware(&desc)) {
                            (void)pthread_mutex_unlock(&_gtwy.firmware_mutex);

                            _restart_app();
                        }
                        (void)pthread_mutex_unlock(&_gtwy.firmware_mutex);
                    }
                }

                VS_LOG_DEBUG("Send info about new Firmware over SNAP");

                if (vs_fldt_server_add_file_type(queued_file, vs_firmware_update_ctx(), true)) {
                    VS_LOG_ERROR("Unable to add new firmware");
                }
                break;

            case VS_UPDATE_TRUST_LIST:
                VS_LOG_DEBUG("Send info about new Trust List over SNAP");

                if (vs_fldt_server_add_file_type(queued_file, vs_tl_update_ctx(), true)) {
                    VS_LOG_ERROR("Unable to add new Trust List");
                }
                break;

            default:
                VS_LOG_ERROR("Unsupported file type %d", queued_file->type);
                break;
            }

            free(queued_file);
        }

#if SIMULATOR
        if (_test_message[0] != 0) { //-V547
            VS_LOG_INFO(_test_message);
        }
#endif
    }
    return NULL;
}

/******************************************************************************/
void
vs_main_start_threads(void) {
    if (!is_threads_started) {
        is_threads_started = true;


        if (0 != pthread_create(&gateway_starter_thread, NULL, _gateway_task, NULL)) {
            VS_LOG_ERROR("Error during starting main gateway thread");
            exit(-1);
        }
    }
}

/******************************************************************************/
