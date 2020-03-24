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

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_CFG_SERVER_H
#define VS_SECURITY_SDK_SNAP_SERVICES_CFG_SERVER_H

#if CFG_SERVER

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/cfg/cfg-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

typedef vs_status_e (*vs_snap_cfg_wifi_cb_t)(const vs_cfg_wifi_configuration_t *configuration);
typedef vs_status_e (*vs_snap_cfg_messenger_cb_t)(const vs_cfg_messenger_config_t *configuration);
typedef vs_status_e (*vs_snap_cfg_channel_cb_t)(const vs_cfg_messenger_channels_t *configuration);
typedef vs_status_e (*vs_snap_cfg_user_cb_t)(const vs_cfg_user_t *configuration);

typedef struct {
    vs_snap_cfg_wifi_cb_t wifi_config_cb;
    vs_snap_cfg_messenger_cb_t messenger_config_cb;
    vs_snap_cfg_channel_cb_t channel_config_cb;
    vs_snap_cfg_user_cb_t user_config_cb;
} vs_snap_cfg_server_service_t;

const vs_snap_service_t *
vs_snap_cfg_server(vs_snap_cfg_server_service_t impl);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // CFG_SERVER

#endif // VS_SECURITY_SDK_SNAP_SERVICES_CFG_SERVER_H
