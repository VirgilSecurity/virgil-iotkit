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

#include <private/cloud_include.h>

static vs_cloud_message_bin_ctx_t _mb_ctx;
static const vs_cloud_message_bin_impl_t *_impl;

typedef struct {
    vs_cloud_mb_process_default_topic_cb_t tl_handler;
    vs_cloud_mb_process_default_topic_cb_t fw_handler;
    vs_cloud_mb_process_custom_topic_cb_t custom_handler;
} vs_cloud_message_bin_handlers_t;

static vs_cloud_message_bin_handlers_t _topic_handlers;

#define VS_HTTPS_INPUT_BUFFER_SIZE (8192)
/*************************************************************************/
static void
_mb_mqtt_ctx_free() {

    _mb_ctx.is_filled = false;
    _mb_ctx.is_active = false;

    VS_IOT_FREE(_mb_ctx.host);
    _mb_ctx.host = NULL;

    VS_IOT_FREE(_mb_ctx.cert);
    _mb_ctx.cert = NULL;

    VS_IOT_FREE(_mb_ctx.login);
    _mb_ctx.login = NULL;

    VS_IOT_FREE(_mb_ctx.password);
    _mb_ctx.password = NULL;

    VS_IOT_FREE(_mb_ctx.client_id);
    _mb_ctx.client_id = NULL;

    VS_IOT_FREE(_mb_ctx.pk);
    _mb_ctx.pk = NULL;

    VS_IOT_FREE(_mb_ctx.topic_list.topic_list);
    _mb_ctx.topic_list.topic_list = NULL;

    VS_IOT_FREE(_mb_ctx.topic_list.topic_len_list);
    _mb_ctx.topic_list.topic_len_list = NULL;

    _mb_ctx.port = 0;
}

#define VS_MB_MQTT_HOST_FIELD "mqtt_host"
#define VS_MB_MQTT_PORT_FIELD "mqtt_port"
#define VS_MB_LOGIN_FIELD "login"
#define VS_MB_PASSWORD_FIELD "password"
#define VS_MB_CLIENT_ID_FIELD "client_id"
#define VS_MB_CERTIFICATE_FIELD "certificate"
#define VS_MB_ROOT_CA_CERTIFICATE_FIELD "ca_certificate"
#define VS_MB_PRIVATE_KEY_FIELD "private_key"
#define VS_MB_AVAILABLE_TOPICS_FIELD "available_topics"

/******************************************************************************/
static int32_t
_str_to_int(const char *str) {
    int32_t res = 0;
    int i;

    for (i = 0; str[i] != '\0'; ++i) {
        if (str[i] < '0' || str[i] > '9') {
            return -1;
        }

        res = res * 10 + str[i] - '0';

        if (res > UINT16_MAX) {
            return -1;
        }
    }
    return res;
}

/******************************************************************************/
static vs_status_e
_get_message_bin_credentials() {
    const char *cloud_url;
    jobj_t jobj;

    if (_mb_ctx.is_filled) {
        return VS_CODE_OK;
    }

    _mb_mqtt_ctx_free();

    VS_LOG_DEBUG("------------------------- LOAD MESSAGE BIN CREDENTIALS -------------------------");

    cloud_url = vs_provision_cloud_url();
    CHECK_NOT_ZERO_RET(cloud_url, VS_CODE_ERR_NOINIT);

    size_t answer_size = VS_HTTPS_INPUT_BUFFER_SIZE;
    char *answer = (char *)VS_IOT_MALLOC(answer_size);
    if (!answer) {
        VS_LOG_ERROR("ALLOCATION FAIL in message bin credentials\r\n");
        return VS_CODE_ERR_NO_MEMORY;
    }

    VS_IOT_MEMSET(&jobj, 0, sizeof(jobj));

    if (VS_CODE_OK == vs_cloud_fetch_message_bin_credentials(cloud_url, answer, &answer_size)) {
        int len;
        int val;
        char *tmp;
        int decode_len;

        CHECK(VS_JSON_ERR_OK == json_parse_start(&jobj, answer, answer_size),
              "[MB] Unable to parse message bin credentials");

        /*----mqtt broker host----*/
        CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_MB_MQTT_HOST_FIELD, &len) && len > 0,
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [mqtt_host]");
        ++len;
        _mb_ctx.host = (char *)VS_IOT_MALLOC((size_t)len);
        CHECK(NULL != _mb_ctx.host, "[MB] Can't allocate memory");

        json_get_val_str(&jobj, VS_MB_MQTT_HOST_FIELD, _mb_ctx.host, len);

        /*----mqtt broker host----*/
        CHECK(VS_JSON_ERR_OK == json_get_val_int(&jobj, VS_MB_MQTT_PORT_FIELD, &val),
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [mqtt_port]");
        CHECK(val > 0 && val < UINT16_MAX, "[MB] cloud_get_message_bin_credentials(...) wrong format [mqtt port]");
        _mb_ctx.port = (uint16_t)val;

        /*----login----*/
        CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_MB_LOGIN_FIELD, &len) && len > 0,
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [login]");

        ++len;
        _mb_ctx.login = (char *)VS_IOT_MALLOC((size_t)len);
        CHECK(NULL != _mb_ctx.login, "[MB] Can't allocate memory");

        json_get_val_str(&jobj, VS_MB_LOGIN_FIELD, _mb_ctx.login, len);

        /*----password----*/
        CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_MB_PASSWORD_FIELD, &len) && len > 0,
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [password]");

        ++len;
        _mb_ctx.password = (char *)VS_IOT_MALLOC((size_t)len);
        CHECK(NULL != _mb_ctx.password, "[MB] Can't allocate memory");

        json_get_val_str(&jobj, VS_MB_PASSWORD_FIELD, _mb_ctx.password, len);

        /*----client_id----*/
        CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_MB_CLIENT_ID_FIELD, &len) && len > 0,
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [client_id]");

        ++len;
        _mb_ctx.client_id = (char *)VS_IOT_MALLOC((size_t)len);
        CHECK(NULL != _mb_ctx.client_id, "[MB] Can't allocate memory");

        json_get_val_str(&jobj, VS_MB_CLIENT_ID_FIELD, _mb_ctx.client_id, len);

        /*----ca certificate----*/
        CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_MB_ROOT_CA_CERTIFICATE_FIELD, &len) && len > 0,
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [certificate]");

        ++len;
        tmp = (char *)VS_IOT_MALLOC((size_t)len);
        CHECK(NULL != tmp, "[MB] Can't allocate memory");

        json_get_val_str(&jobj, VS_MB_ROOT_CA_CERTIFICATE_FIELD, tmp, len);

        decode_len = base64decode_len(tmp, len);

        if (0 >= decode_len) {
            VS_IOT_FREE(tmp);
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) wrong size [ca_certificate]");
            goto terminate;
        }

        _mb_ctx.root_ca_cert = (char *)VS_IOT_MALLOC((size_t)decode_len);
        if (NULL == _mb_ctx.root_ca_cert) {
            VS_IOT_FREE(tmp);
            VS_LOG_ERROR("[MB] Can't allocate memory");
            goto terminate;
        }

        base64decode(tmp, len, (uint8_t *)_mb_ctx.root_ca_cert, &decode_len);
        VS_IOT_FREE(tmp);

        /*----certificate----*/
        CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_MB_CERTIFICATE_FIELD, &len) && len > 0,
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [certificate]");

        ++len;
        tmp = (char *)VS_IOT_MALLOC((size_t)len);
        CHECK(NULL != tmp, "[MB] Can't allocate memory");

        json_get_val_str(&jobj, VS_MB_CERTIFICATE_FIELD, tmp, len);

        decode_len = base64decode_len(tmp, len);

        if (0 >= decode_len) {
            VS_IOT_FREE(tmp);
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) wrong size [certificate]");
            goto terminate;
        }

        _mb_ctx.cert = (char *)VS_IOT_MALLOC((size_t)decode_len);
        if (NULL == _mb_ctx.cert) {
            VS_IOT_FREE(tmp);
            VS_LOG_ERROR("[MB] Can't allocate memory");
            goto terminate;
        }

        base64decode(tmp, len, (uint8_t *)_mb_ctx.cert, &decode_len);
        VS_IOT_FREE(tmp);

        /*----private_key----*/
        CHECK(VS_JSON_ERR_OK == json_get_val_str_len(&jobj, VS_MB_PRIVATE_KEY_FIELD, &len) && len > 0,
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [private_key]");

        ++len;
        tmp = (char *)VS_IOT_MALLOC((size_t)len);
        CHECK(NULL != tmp, "[MB] Can't allocate memory");

        json_get_val_str(&jobj, VS_MB_PRIVATE_KEY_FIELD, tmp, len);

        decode_len = base64decode_len(tmp, len);

        if (0 >= decode_len) {
            VS_IOT_FREE(tmp);
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) wrong size [certificate]");
            goto terminate;
        }

        _mb_ctx.pk = (char *)VS_IOT_MALLOC((size_t)decode_len);
        if (NULL == _mb_ctx.pk) {
            VS_IOT_FREE(tmp);
            VS_LOG_ERROR("[MB] Can't allocate memory");
            goto terminate;
        }

        base64decode(tmp, len, (uint8_t *)_mb_ctx.pk, &decode_len);
        VS_IOT_FREE(tmp);

        /*----available_topics----*/
        int topic_count;
        CHECK(VS_JSON_ERR_OK == json_get_array_object(&jobj, VS_MB_AVAILABLE_TOPICS_FIELD, &topic_count) &&
                      topic_count > 0,
              "[MB] cloud_get_message_bin_credentials(...) answer not contain [available_topics]");

        _mb_ctx.topic_list.topic_count = (size_t)topic_count;

        {
            uint16_t total_topic_names_len = 0;
            uint16_t i;
            len = 0;
            int offset = 0;

            _mb_ctx.topic_list.topic_len_list =
                    (uint16_t *)VS_IOT_MALLOC(_mb_ctx.topic_list.topic_count * sizeof(uint16_t));
            CHECK(NULL != _mb_ctx.topic_list.topic_len_list, "[MB] Can't allocate memory");

            for (i = 0; i < _mb_ctx.topic_list.topic_count; i++) {
                json_array_get_str_len(&jobj, i, &len);

                CHECK(len + 1 <= UINT16_MAX,
                      "[MB] cloud_get_message_bin_credentials(...) [available_topics] name len is too big");

                _mb_ctx.topic_list.topic_len_list[i] = (uint16_t)(len + 1);
                total_topic_names_len += _mb_ctx.topic_list.topic_len_list[i];
            }

            _mb_ctx.topic_list.topic_list = (char *)VS_IOT_MALLOC(total_topic_names_len);
            CHECK(NULL != _mb_ctx.topic_list.topic_list, "[MB] Can't allocate memory");

            for (i = 0; i < _mb_ctx.topic_list.topic_count; i++) {
                json_array_get_str(&jobj, i, _mb_ctx.topic_list.topic_list + offset, total_topic_names_len - offset);

                json_array_get_str_len(&jobj, i, &len);
                offset += len;
                _mb_ctx.topic_list.topic_list[offset] = '\0';
                offset++;
            }
        }

        _mb_ctx.is_filled = true;
        json_parse_stop(&jobj);
        VS_IOT_FREE(answer);
        VS_LOG_DEBUG("[MB] Credentials are loaded successfully");
        return VS_CODE_OK;
    }

terminate:
    json_parse_stop(&jobj);
    _mb_mqtt_ctx_free();
    VS_IOT_FREE(answer);
    return VS_CODE_ERR_CLOUD;
}

/******************************************************************************/
vs_status_e
vs_cloud_message_bin_init(const vs_cloud_message_bin_impl_t *impl) {
    _impl = NULL;
    CHECK_NOT_ZERO_RET(impl, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(impl->init, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(impl->connect_subscribe, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(impl->process, VS_CODE_ERR_NULLPTR_ARGUMENT);
    _mb_mqtt_ctx_free();
    _impl = impl;

    VS_IOT_MEMSET(&_topic_handlers, 0, sizeof(vs_cloud_message_bin_handlers_t));

    return VS_CODE_OK;
}

/*************************************************************************/
static void
_process_topic(const char *topic, uint16_t topic_sz, const uint8_t *data, uint16_t length) {
    char *ptr;
    uint8_t upd_file_url[VS_UPD_URL_STR_SIZE];
    vs_cloud_mb_process_default_topic_cb_t default_handler = NULL;

    vs_status_e res = VS_CODE_ERR_NOT_IMPLEMENTED;

    // Process firmware topic
    if (_topic_handlers.fw_handler) {
        ptr = VS_IOT_STRSTR(topic, VS_FW_TOPIC_MASK);
        if (ptr != NULL && topic == ptr) {
            res = vs_cloud_parse_firmware_manifest((char *)data, length, (char *)upd_file_url);
            default_handler = _topic_handlers.fw_handler;
        }
    }

    // Process tl topic if firmware topic isn't found
    if (_topic_handlers.tl_handler && !default_handler) {
        ptr = VS_IOT_STRSTR(topic, VS_TL_TOPIC_MASK);
        if (ptr != NULL && topic == ptr) {
            res = vs_cloud_parse_tl_mainfest((char *)data, length, (char *)upd_file_url);
            default_handler = _topic_handlers.tl_handler;
        }
    }

    // Process default topic if it's handler is registered
    if (default_handler) {
        if (VS_CODE_OK == res) {
            default_handler(upd_file_url, VS_IOT_STRLEN((char *)upd_file_url));
        } else if (VS_CODE_ERR_NOT_FOUND == res) {
            VS_LOG_INFO("[MB] Manifest contains old version\n");
        } else {
            VS_LOG_INFO("[MB] Error parse manifest\n");
        }
        return;
    }

    // Call the custom topic handler if any default topics weren't found or any default handlers weren't registered
    if (_topic_handlers.custom_handler) {
        _topic_handlers.custom_handler(topic, topic_sz, data, length);
    }
}

/******************************************************************************/
vs_status_e
vs_cloud_message_bin_register_default_handler(vs_cloud_mb_topic_id_t topic_id,
                                              vs_cloud_mb_process_default_topic_cb_t handler) {

    switch (topic_id) {
    case VS_CLOUD_MB_TOPIC_FW:
        _topic_handlers.fw_handler = handler;
        break;
    case VS_CLOUD_MB_TOPIC_TL:
        _topic_handlers.tl_handler = handler;
        break;
    default:
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_cloud_message_bin_register_custom_handler(vs_cloud_mb_process_custom_topic_cb_t handler) {
    _topic_handlers.custom_handler = handler;
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_cloud_message_bin_process(void) {

    CHECK_NOT_ZERO_RET(_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);

    bool provision_is_present = _mb_ctx.is_filled || (VS_CODE_OK == _get_message_bin_credentials());

    if (provision_is_present) {
        if (!_mb_ctx.is_active) {

            VS_LOG_DEBUG("[MB]Connecting to broker host %s : %u ...", _mb_ctx.host, _mb_ctx.port);

            if (VS_CODE_OK == _impl->init(_mb_ctx.host,
                                          _mb_ctx.port,
                                          (const char *)_mb_ctx.cert,
                                          (const char *)_mb_ctx.pk,
                                          (const char *)_mb_ctx.root_ca_cert) &&
                VS_CODE_OK == _impl->connect_subscribe(_mb_ctx.client_id,
                                                       _mb_ctx.login,
                                                       _mb_ctx.password,
                                                       &_mb_ctx.topic_list,
                                                       _process_topic)) {
                _mb_ctx.is_active = true;
            } else {
                VS_LOG_DEBUG("[MB]Connection failed");
            }
            return VS_CODE_OK;
        }
        return _impl->process();
    }
    return VS_CODE_ERR_CLOUD;
}