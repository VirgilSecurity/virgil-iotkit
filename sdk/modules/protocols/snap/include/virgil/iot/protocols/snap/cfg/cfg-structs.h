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

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_CFG_STRUCTS_H
#define VS_SECURITY_SDK_SNAP_SERVICES_CFG_STRUCTS_H

#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/protocols/snap/snap-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#define VS_CFG_STR_MAX (64)

typedef struct {
    uint8_t ssid[VS_CFG_STR_MAX];
    uint8_t pass[VS_CFG_STR_MAX];
    uint8_t account[VS_CFG_STR_MAX];
} vs_cfg_wifi_configuration_t;

#define VS_MESSENGER_CFG_VERSION (1)     /**< Current version of messenger configuration */
#define VS_HOST_NAME_MAX_SZ (128)        /**< Maximum size of string with host name */
#define VS_MESSENGER_CHANNEL_MAX_SZ (32) /**< Maximum size of Messenger's channel name */
#define VS_MESSENGER_CHANNEL_NUM_MAX (1) /**< Suported amount of channels */

/** Messenger's configuration */
typedef struct {
    uint8_t version;                              /**< Version of #vs_messenger_config_t structure */
    char enjabberd_host[VS_HOST_NAME_MAX_SZ];     /**< Enjabberd host */
    uint16_t enjabberd_port;                      /**< Enjabberd port */
    char messenger_base_url[VS_HOST_NAME_MAX_SZ]; /**< Virgil messenger service base URL */
} vs_cfg_messenger_config_t;

/** Messenger's channels to accept and connect to */
typedef struct {
    uint8_t channels_num;                                                    /**< Amount of available XMPP channels */
    char channel[VS_MESSENGER_CHANNEL_NUM_MAX][VS_MESSENGER_CHANNEL_MAX_SZ]; /**< Available XMPP channels */
} vs_cfg_messenger_channels_t;


/** User data configuration */
typedef struct {
    uint8_t data_type; /**< User data type */
    uint32_t data_sz;  /**< User data size */
    uint8_t data[];    /**< User data */
} vs_cfg_user_t;

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_SECURITY_SDK_SNAP_SERVICES_CFG_STRUCTS_H
