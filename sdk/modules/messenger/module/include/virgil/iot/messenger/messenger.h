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

#ifndef VS_MESSENGER_H
#define VS_MESSENGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <global-hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/messenger/internal/virgil.h>
#include <virgil/iot/messenger/internal/enjabberd.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

typedef void (*vs_messenger_rx_cb_t)(const char *sender, const char *message);

#define VS_MESSENGER_CFG_VERSION (1)     /**< Current version of messenger configuration */
#define VS_HOST_NAME_MAX_SZ (128)        /**< Maximum size of string with host name */
#define VS_MESSENGER_CHANNEL_MAX_SZ (32) /**< Maximum size of Messenger's channel name */
#define VS_MESSENGER_CHANNEL_NUM_MAX (1) /**< Supported amount of channels */

/** Messenger's configuration */
typedef struct {
    uint8_t version;                              /**< Version of #vs_messenger_config_t structure */
    char enjabberd_host[VS_HOST_NAME_MAX_SZ];     /**< Enjabberd host */
    uint16_t enjabberd_port;                      /**< Enjabberd port */
    char messenger_base_url[VS_HOST_NAME_MAX_SZ]; /**< Virgil messenger service base URL */
} vs_messenger_config_t;

/** Messenger's channels to accept and connect to */
typedef struct {
    uint8_t channels_num;                                                    /**< Amount of available XMPP channels */
    char channel[VS_MESSENGER_CHANNEL_NUM_MAX][VS_MESSENGER_CHANNEL_MAX_SZ]; /**< Available XMPP channels */
} vs_messenger_channels_t;

// This function saves configuration data into persistent storage
// Use it only once, on receive  of configuration data from Cloud
// If messenger is already started, then new configuration will be
// used on the next boot.
vs_status_e
vs_messenger_configure(const vs_messenger_config_t *config);

// This function saves available channels names into persistent storage
// If messenger is already started, then new channels list will be
// used on the next boot.
vs_status_e
vs_messenger_set_channels(const char *identity, const vs_messenger_channels_t *channels);

vs_status_e
vs_messenger_start(const char *identity, vs_messenger_rx_cb_t rx_cb);

vs_status_e
vs_messenger_send(const char *recipient, const char *message);

const char *
vs_messenger_default_channel(void);

vs_status_e
vs_messenger_stop(void);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_MESSENGER_H
