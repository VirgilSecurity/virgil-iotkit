//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#ifndef VS_IOT_SDK_CLOUD_CONFIG_H
#define VS_IOT_SDK_CLOUD_CONFIG_H

#define VS_MSG_BIN_MQTT_PORT 8883

#define VS_MESSAGE_BIN_BROKER_URL "mqtt-dev.virgilsecurity.com"
#define VS_CLOUD_HOST "https://things-dev.virgilsecurity.com"
#define VS_THING_EP "thing"
#define VS_AWS_ID "aws"
#define VS_MQTT_ID "mqtt"

#define VS_HTTPS_INPUT_BUFFER_SIZE (8192)

#define VS_MANIFEST "manifest"
#define VS_FW_URL "firmware_url"

#define VS_MANUFACTURE_ID "manufacturer_id"
#define VS_MODEL_ID "model_type"
#define VS_FW_VERSION "version"

#define VS_FW_TIMESTAMP "build_timestamp"
#define VS_FW_TOPIC_MASK "fw/"

#define VS_TL_TOPIC_MASK "tl/"

#define VS_TL_URL_FIELD "trustlist_url"
#define VS_TL_VERSION_FIELD "version"
#define VS_TL_TYPE_FILE "type"

#endif //VS_IOT_SDK_CLOUD_CONFIG_H
