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

#include "aws_iot_log.h"
#include "aws_iot_error.h"
#include <string.h>
#include <stdio.h>
#include <aws_iot_mqtt_client_interface.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/cloud/cloud.h>

#define VS_MQTT_TIMEOUT_MS (500)

typedef struct {
    IoT_Client_Init_Params init_params;
    IoT_Client_Connect_Params connect_params;
    AWS_IoT_Client client;
} vs_aws_mqtt_message_handler_t;

static vs_aws_mqtt_message_handler_t _mb_mqtt_handler;

static vs_status_e
_init_aws_mqtt_client(const char *host,
                      uint16_t port,
                      const char *device_cert,
                      const char *priv_key,
                      const char *ca_cert);

static vs_status_e
_connect_and_subscribe_to_topics(const char *client_id,
                                 const char *login,
                                 const char *password,
                                 const vs_cloud_mb_topics_list_t *topic_list,
                                 vs_cloud_mb_process_custom_topic_cb_t process_topic);
static vs_status_e
_mqtt_process(void);

static const vs_cloud_message_bin_impl_t _impl = {
        .init = _init_aws_mqtt_client,
        .connect_subscribe = _connect_and_subscribe_to_topics,
        .process = _mqtt_process,
};

/******************************************************************************/
static void
_disconnect_callback(AWS_IoT_Client *client, void *data) {
    VS_LOG_WARNING("MQTT Disconnect");
    IoT_Error_t rc;

    if (client) {
        return;
    }

    (void)(data);

    if (aws_iot_is_autoreconnect_enabled(client)) {
        VS_LOG_INFO("Auto Reconnect is enabled, Reconnecting attempt will start now");
    } else {
        VS_LOG_WARNING("Auto Reconnect not enabled. Starting manual reconnect...");
        rc = aws_iot_mqtt_attempt_reconnect(client);
        if (NETWORK_RECONNECTED == rc) {
            VS_LOG_WARNING("Manual Reconnect Successful");
        } else {
            VS_LOG_WARNING("Manual Reconnect Failed - %d", rc);
        }
    }
}

/*************************************************************************/
static void
_group_callback(AWS_IoT_Client *client,
                char *topic,
                uint16_t topic_sz,
                IoT_Publish_Message_Params *params,
                void *pData) {
    uint8_t *p = (uint8_t *)params->payload;
    p[params->payloadLen] = 0;
    vs_cloud_mb_process_custom_topic_cb_t process_topic = (vs_cloud_mb_process_custom_topic_cb_t)pData;

    VS_LOG_DEBUG("[MB] Message from topic %s", topic);
    VS_LOG_DEBUG("[MB] _group_callback params->payloadLen=%d", (int)params->payloadLen);
    if (params->payloadLen > UINT16_MAX) {
        VS_LOG_ERROR("[MB] Topic message is too big");
        return;
    }

    if (process_topic) {
        process_topic(topic, topic_sz, p, (uint16_t)params->payloadLen);
    }
}

/******************************************************************************/
static char *
_get_topic_name_by_index(const vs_cloud_mb_topics_list_t *topic_list, uint32_t index) {
    uint32_t i;
    char *topic_list_ptr = topic_list->topic_list;

    if (index >= topic_list->topic_count)
        return NULL;

    for (i = 0; i < index; ++i) {
        topic_list_ptr += topic_list->topic_len_list[i];
    }
    return topic_list_ptr;
}

/******************************************************************************/
static IoT_Error_t
_connect_internal(vs_aws_mqtt_message_handler_t *handler,
                  const char *client_id,
                  const char *login,
                  const char *password) {
    IoT_Error_t rc;
    IoT_Client_Connect_Params *pConnectParams = &handler->connect_params;
    pConnectParams->keepAliveIntervalInSec = 10;
    pConnectParams->isCleanSession = true;
    pConnectParams->MQTTVersion = MQTT_3_1_1;
    pConnectParams->pClientID = (char *)client_id;
    pConnectParams->clientIDLen = (uint16_t)strlen(client_id);
    pConnectParams->isWillMsgPresent = false;
    pConnectParams->pUsername = (char *)login;
    pConnectParams->pPassword = (char *)password;
    if (login) {
        pConnectParams->usernameLen = (uint16_t)strlen(login);
    } else {
        pConnectParams->usernameLen = 0;
    }
    if (password) {
        pConnectParams->passwordLen = (uint16_t)strlen(password);
    } else {
        pConnectParams->passwordLen = 0;
    }

    VS_LOG_INFO("Connecting...");
    rc = aws_iot_mqtt_connect(&handler->client, pConnectParams);
    if (SUCCESS != rc) {
        VS_LOG_ERROR("Error(%d) connecting to %s:%d", rc, handler->init_params.pHostURL, handler->init_params.port);
        return rc;
    }

    /*
     * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
     *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
     *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
     */
    rc = aws_iot_mqtt_autoreconnect_set_status(&handler->client, true);
    if (SUCCESS != rc) {
        VS_LOG_ERROR("Unable to set Auto Reconnect to true - %d", rc);
    }
    return rc;
}

#if 0
/******************************************************************************/
static IoT_Error_t
_connect_and_subscribe_one_topic(
        vs_aws_mqtt_message_handler_t *handler,
        const char *client_id,
        const char *topic,
        const char *login,
        const char *password,
        QoS qos,
        void (*iot_get_msg_handler)(AWS_IoT_Client *, char *, uint16_t, IoT_Publish_Message_Params *, void *),
        void *iot_get_msg_handler_data) {

    IoT_Error_t rc;
    rc = _aws_connect_internal(handler, client_id, login, password, iot_get_msg_handler);
    if (SUCCESS != rc) {
        return rc;
    }

    VS_LOG_INFO("Subscribing to topic %s", topic);
    rc = aws_iot_mqtt_subscribe(
            &handler->client, topic, (uint16_t)strlen(topic), qos, iot_get_msg_handler, iot_get_msg_handler_data);
    if (SUCCESS != rc) {
        VS_LOG_ERROR("Error subscribing %s: %d ", topic, rc);
    }

    return rc;
}

/******************************************************************************/
static bool
_publish(vs_aws_mqtt_message_handler_t *handler, const char *topic, uint8_t *data, size_t data_sz) {
    IoT_Publish_Message_Params param;
    param.qos = QOS0;
    param.payload = data;
    param.payloadLen = data_sz;
    param.isRetained = 0;
    IoT_Error_t rc;
    // Max time the yield function will wait for read messages
    aws_iot_mqtt_yield(&handler->client, VS_MQTT_TIMEOUT_MS);

    if (SUCCESS != (rc = aws_iot_mqtt_publish(&handler->client, topic, (uint16_t)strlen(topic), &param))) {
        VS_LOG_ERROR("Error send to topic %s: %d ", topic, rc);
        return false;
    }
    aws_iot_mqtt_yield(&handler->client, VS_MQTT_TIMEOUT_MS);
    return true;
}
#endif

/*************************************************************************/
static vs_status_e
_init_aws_mqtt_client(const char *host,
                      uint16_t port,
                      const char *device_cert,
                      const char *priv_key,
                      const char *ca_cert) {

    IoT_Error_t rc;
    vs_status_e res = VS_CODE_OK;
    _mb_mqtt_handler.init_params = iotClientInitParamsDefault;
    _mb_mqtt_handler.connect_params = iotClientConnectParamsDefault;

    IoT_Client_Init_Params *mqttInitParams = &_mb_mqtt_handler.init_params;

    memset(mqttInitParams, 0, sizeof(IoT_Client_Init_Params));

    mqttInitParams->enableAutoReconnect = false; // We enable this later below
    mqttInitParams->pHostURL = (char *)host;
    mqttInitParams->port = port;
    mqttInitParams->pDeviceCertLocation = (char *)device_cert;
    mqttInitParams->pDevicePrivateKeyLocation = (char *)priv_key;
    mqttInitParams->pRootCALocation = (char *)ca_cert;
    mqttInitParams->mqttCommandTimeout_ms = 20000;
    mqttInitParams->tlsHandshakeTimeout_ms = 15000;
    mqttInitParams->isSSLHostnameVerify = true;
    mqttInitParams->disconnectHandler = _disconnect_callback;
    mqttInitParams->disconnectHandlerData = NULL;

    rc = aws_iot_mqtt_init(&_mb_mqtt_handler.client, mqttInitParams);
    if (SUCCESS != rc) {
        VS_LOG_ERROR("iot_mqtt_init returned error : %d ", rc);
        res = VS_CODE_ERR_CLOUD;
    }

    return res;
}

/*************************************************************************/
static vs_status_e
_connect_and_subscribe_to_topics(const char *client_id,
                                 const char *login,
                                 const char *password,
                                 const vs_cloud_mb_topics_list_t *topic_list,
                                 vs_cloud_mb_process_custom_topic_cb_t process_topic) {

    vs_status_e res = VS_CODE_ERR_CLOUD;
    IoT_Error_t rc;
    uint32_t i;

    if (SUCCESS != _connect_internal(&_mb_mqtt_handler, client_id, login, password)) {
        return VS_CODE_ERR_CLOUD;
    }

    for (i = 0; i < topic_list->topic_count; ++i) {
        char *topic_name = _get_topic_name_by_index(topic_list, i);

        if (0 == topic_list->topic_len_list[i]) {
            continue;
        }

        VS_LOG_INFO("Subscribing to topic %s", topic_name);
        rc = aws_iot_mqtt_subscribe(&_mb_mqtt_handler.client,
                                    topic_name,
                                    topic_list->topic_len_list[i] - (uint16_t)1,
                                    QOS1,
                                    _group_callback,
                                    (void *)process_topic);
        if (SUCCESS != rc) {
            VS_LOG_ERROR("Error subscribing %s : %d ", topic_name, rc);
        } else {
            VS_LOG_INFO("Success subscribing %s", topic_name);
            res = VS_CODE_OK;
        }
    }

    return res;
}

/*************************************************************************/
static vs_status_e
_mqtt_process(void) {
    return (SUCCESS == aws_iot_mqtt_yield(&_mb_mqtt_handler.client, VS_MQTT_TIMEOUT_MS)) ? VS_CODE_OK
                                                                                         : VS_CODE_ERR_CLOUD;
}

/******************************************************************************/
const vs_cloud_message_bin_impl_t *
vs_aws_message_bin_impl(void) {
    return &_impl;
}
