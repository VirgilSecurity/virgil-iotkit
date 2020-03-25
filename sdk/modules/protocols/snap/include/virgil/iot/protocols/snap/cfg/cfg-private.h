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


#ifndef VS_SECURITY_SDK_SNAP_SERVICES_CFG_PRIVATE_H
#define VS_SECURITY_SDK_SNAP_SERVICES_CFG_PRIVATE_H

#include <virgil/iot/protocols/snap/cfg/cfg-server.h>
#include <virgil/iot/protocols/snap/cfg/cfg-structs.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/protocols/snap/snap-structs.h>

// mute "error: multi-character character constant" message
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
typedef enum { VS_CFG_SERVICE_ID = HTONL_IN_COMPILE_TIME('_CFG') } vs_cfg_t;

typedef enum {
    VS_CFG_WIFI = HTONL_IN_COMPILE_TIME('WIFI'), /* configure WIFI creds */
    VS_CFG_MSCR = HTONL_IN_COMPILE_TIME('MSCR'), /* configure MeSsenger CReds */
    VS_CFG_MSCH = HTONL_IN_COMPILE_TIME('MSCH'), /* configure MeSsenger CHannel */
    VS_CFG_USER = HTONL_IN_COMPILE_TIME('USER'), /* configure USER data */
} vs_snap_cfg_element_e;
#pragma GCC diagnostic pop

typedef struct __attribute__((__packed__)) {
    uint8_t ssid[VS_CFG_STR_MAX];
    uint8_t pass[VS_CFG_STR_MAX];
    uint8_t account[VS_CFG_STR_MAX];
} vs_cfg_conf_wifi_request_t;

typedef struct __attribute__((__packed__)) {
    uint8_t version;
    char enjabberd_host[VS_HOST_NAME_MAX_SZ];
    uint16_t enjabberd_port;
    char messenger_base_url[VS_HOST_NAME_MAX_SZ];
} vs_cfg_messenger_config_request_t;

typedef struct __attribute__((__packed__)) {
    uint8_t channels_num;
    char channel[VS_MESSENGER_CHANNEL_NUM_MAX][VS_MESSENGER_CHANNEL_MAX_SZ];
} vs_cfg_messenger_channels_request_t;

typedef struct __attribute__((__packed__)) {
    uint8_t data_type;
    uint32_t data_sz;
    uint8_t data[];
} vs_cfg_user_config_request_t;

#endif // VS_SECURITY_SDK_SNAP_SERVICES_CFG_PRIVATE_H
