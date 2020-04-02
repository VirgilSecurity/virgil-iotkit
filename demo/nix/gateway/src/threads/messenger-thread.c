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

#include "threads/messenger-thread.h"
#include <virgil/iot/messenger/messenger.h>
#include <virgil/iot/logger/logger.h>

static pthread_t _messenger_thread;

// TODO: create some mechanism to calculate Identity
static const char *_identity = "gw_test_020420";

// TODO: Use configuration from User's device
static const char *_enjabberd_host = "xmpp-stg.virgilsecurity.com";
static const uint16_t _enjabberd_port = 5222;
static const char *_service_base_url = "https://messenger-stg.virgilsecurity.com";

// TODO: Use channels list from User's device
static const char *_messenger_channel = "WizardMD";

/*************************************************************************/
static void
_messenger_rx_cb(const char *sender, const char *message) {
    if (sender && message) {
        VS_LOG_DEBUG("Message from: %s  <%s>", sender, message);
    }
}

/*************************************************************************/
static void *
_messenger_task(void *params) {
    vs_messenger_config_t config;
    vs_messenger_channels_t channels;

    // Prepare configuration
    VS_IOT_MEMSET(&config, 0, sizeof(config));
    config.version = VS_MESSENGER_CFG_VERSION;
    VS_IOT_MEMCPY(config.messenger_base_url, _service_base_url, strlen(_service_base_url));
    VS_IOT_MEMCPY(config.enjabberd_host, _enjabberd_host, strlen(_enjabberd_host));
    config.enjabberd_port = _enjabberd_port;

    // Configure Messenger
    STATUS_CHECK(vs_messenger_configure(&config), "Messenger configuration error");

    // Prepare the list of supported channels
    VS_IOT_MEMSET(&channels, 0, sizeof(channels));
    channels.channels_num = 1;
    VS_IOT_MEMCPY(channels.channel[0], _messenger_channel, strlen(_messenger_channel));

    // Set available channels for Messenger
    STATUS_CHECK(vs_messenger_set_channels(_identity, &channels), "Messenger channels setup error");

    // Start Messenger
    STATUS_CHECK(vs_messenger_start(_identity, _messenger_rx_cb), "Messenger configuration error");

    vs_log_thread_descriptor("msgr thr");
    VS_LOG_DEBUG("Messenger thread started");

#if 0
        while (true) {
            THREAD_CANCEL_DISABLE;
            res = vs_cloud_message_bin_process();
            THREAD_CANCEL_RESTORE;
            if (VS_CODE_OK == res) {
                vs_impl_msleep(500);
            } else {
                vs_impl_msleep(5000);
            }
        }
#endif

terminate:

    // Stop Messenger
    vs_messenger_stop();

    return NULL;
}

/*************************************************************************/
pthread_t *
vs_messenger_start_thread() {
    static bool is_threads_started = 0;

    if (!is_threads_started) {

        is_threads_started = (0 == pthread_create(&_messenger_thread, NULL, _messenger_task, NULL));
        if (!is_threads_started) {
            return NULL;
        }
    }
    return &_messenger_thread;
}

/*************************************************************************/
