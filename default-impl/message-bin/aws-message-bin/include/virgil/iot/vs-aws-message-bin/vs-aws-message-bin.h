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

#ifndef VS_AWS_DEFAULT_MESSAGE_BIN_IMPL_H
#define VS_AWS_DEFAULT_MESSAGE_BIN_IMPL_H

#include "aws_iot_mqtt_client_interface.h"
#include <virgil/iot/cloud/cloud.h>

typedef struct {
    IoT_Client_Init_Params init_params;
    IoT_Client_Connect_Params connect_params;
    AWS_IoT_Client client;
} iot_message_handler_t;

IoT_Error_t
iot_init(iot_message_handler_t *handler,
         const char *host,
         uint16_t port,
         bool is_ssl_hostname_verify,
         const char *deviceCert,
         const char *priv_key,
         const char *rootCACert);

IoT_Error_t
iot_connect_and_subscribe_multiple_topics(
        iot_message_handler_t *handler,
        const char *client_id,
        const vs_cloud_mb_topics_list_t *topic_list,
        const char *login,
        const char *password,
        QoS qos,
        void (*iot_get_msg_handler)(AWS_IoT_Client *, char *, uint16_t, IoT_Publish_Message_Params *, void *),
        void *iot_get_msg_handler_data);

IoT_Error_t
iot_connect_and_subscribe_topic(
        iot_message_handler_t *handler,
        const char *client_id,
        const char *topic,
        const char *login,
        const char *password,
        QoS qos,
        void (*iot_get_msg_handler)(AWS_IoT_Client *, char *, uint16_t, IoT_Publish_Message_Params *, void *),
        void *iot_get_msg_handler_data);

bool
iot_send(iot_message_handler_t *handler, const char *topic, uint8_t *data, size_t data_sz);

bool
iot_process(iot_message_handler_t *handler);

const vs_cloud_mesage_bin_impl_t *
vs_aws_message_bin_impl(void);

#endif // VS_AWS_DEFAULT_MESSAGE_BIN_IMPL_H
