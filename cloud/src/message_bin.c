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

#include <virgil/iot/cloud/private/cloud_include.h>

static vs_cloud_message_bin_ctx_t _mb_ctx;
static const vs_cloud_message_bin_impl_t *_impl;

/*************************************************************************/
static void
_mb_mqtt_ctx_free() {

    _mb_ctx.is_filled = false;
    _mb_ctx.is_active = false;

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

/******************************************************************************/
static vs_status_e
_get_message_bin_credentials() {

    if (_mb_ctx.is_filled) {
        return VS_CODE_OK;
    }

    _mb_mqtt_ctx_free();

    VS_LOG_DEBUG("------------------------- LOAD MESSAGE BIN CREDENTIALS -------------------------");

    size_t answer_size = VS_HTTPS_INPUT_BUFFER_SIZE;
    char *answer = (char *)VS_IOT_MALLOC(answer_size);
    if (!answer) {
        VS_LOG_ERROR("ALLOCATION FAIL in message bin credentials\r\n");
        return VS_CODE_ERR_NO_MEMORY;
    }

    if (VS_CODE_OK == vs_cloud_fetch_message_bin_credentials(answer, &answer_size)) {
        jobj_t jobj;
        int len;

        _mb_ctx.host = VS_MESSAGE_BIN_BROKER_URL; /*host*/
        _mb_ctx.port = VS_MSG_BIN_MQTT_PORT;      /*port*/

        if (json_parse_start(&jobj, answer, answer_size) != VS_JSON_ERR_OK) {
            goto clean;
        }

        /*----login----*/
        if (json_get_val_str_len(&jobj, "login", &len) != VS_JSON_ERR_OK || len < 0) {
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) answer not contain [login]!!!\r\n");
            goto clean;
        }
        ++len;
        _mb_ctx.login = (char *)VS_IOT_MALLOC((size_t)len);
        json_get_val_str(&jobj, "login", _mb_ctx.login, len);

        /*----password----*/
        if (json_get_val_str_len(&jobj, "password", &len) != VS_JSON_ERR_OK || len < 0) {
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) answer not contain [password]");
            goto clean;
        }
        ++len;
        _mb_ctx.password = (char *)VS_IOT_MALLOC((size_t)len);
        json_get_val_str(&jobj, "password", _mb_ctx.password, len);

        /*----client_id----*/
        if (json_get_val_str_len(&jobj, "client_id", &len) != VS_JSON_ERR_OK || len < 0) {
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) answer not contain [client_id]");
            goto clean;
        }
        ++len;
        _mb_ctx.client_id = (char *)VS_IOT_MALLOC((size_t)len);
        json_get_val_str(&jobj, "client_id", _mb_ctx.client_id, len);

        /*----certificate----*/
        if (json_get_val_str_len(&jobj, "certificate", &len) != VS_JSON_ERR_OK || len < 0) {
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) answer not contain [certificate]");
            goto clean;
        }
        ++len;

        char *tmp = (char *)VS_IOT_MALLOC((size_t)len);
        json_get_val_str(&jobj, "certificate", tmp, len);

        int decode_len = base64decode_len(tmp, len);

        if (0 >= decode_len) {
            VS_IOT_FREE(tmp);
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) wrong size [certificate]");
            goto clean;
        }

        _mb_ctx.cert = (char *)VS_IOT_MALLOC((size_t)decode_len);

        base64decode(tmp, len, (uint8_t *)_mb_ctx.cert, &decode_len);
        VS_IOT_FREE(tmp);

        /*----private_key----*/
        if (json_get_val_str_len(&jobj, "private_key", &len) != VS_JSON_ERR_OK || len < 0) {
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) answer not contain [private_key]");
            goto clean;
        }
        ++len;
        tmp = (char *)VS_IOT_MALLOC((size_t)len);
        json_get_val_str(&jobj, "private_key", tmp, len);

        decode_len = base64decode_len(tmp, len);

        if (0 >= decode_len) {
            VS_IOT_FREE(tmp);
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) wrong size [certificate]");
            goto clean;
        }

        _mb_ctx.pk = (char *)VS_IOT_MALLOC((size_t)decode_len);

        base64decode(tmp, len, (uint8_t *)_mb_ctx.pk, &decode_len);
        VS_IOT_FREE(tmp);

        /*----available_topics----*/
        int topic_count;
        if (json_get_array_object(&jobj, "available_topics", &topic_count) != VS_JSON_ERR_OK || topic_count < 0) {
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) answer not contain [available_topics]");
            goto clean;
        }
        _mb_ctx.topic_list.topic_count = (size_t)topic_count;

        if (0 == _mb_ctx.topic_list.topic_count) {
            VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) [available_topics] is empty!");
            goto clean;
        } else {
            uint16_t i, total_topic_names_len = 0;
            len = 0;

            _mb_ctx.topic_list.topic_len_list = (uint16_t *)VS_IOT_MALLOC(_mb_ctx.topic_list.topic_count * sizeof(uint16_t));
            if (! _mb_ctx.topic_list.topic_len_list) {
                VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) [topic_len_list] allocation error");
                goto clean;
            }

            for (i = 0; i < _mb_ctx.topic_list.topic_count; i++) {
                json_array_get_str_len(&jobj, i, &len);

                if (len + 1 > UINT16_MAX) {
                    VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) [available_topics] name len is too big");
                    goto clean;
                }

                _mb_ctx.topic_list.topic_len_list[i] = (uint16_t)(len + 1);
                total_topic_names_len += _mb_ctx.topic_list.topic_len_list[i];
            }

            _mb_ctx.topic_list.topic_list = (char *)VS_IOT_MALLOC(total_topic_names_len);
            if (! _mb_ctx.topic_list.topic_list) {
                VS_LOG_ERROR("[MB] cloud_get_message_bin_credentials(...) [topic_list] allocation error");
                goto clean;
            }

            int offset = 0;

            for (i = 0; i < _mb_ctx.topic_list.topic_count; i++) {
                json_array_get_str(&jobj, i, _mb_ctx.topic_list.topic_list + offset, total_topic_names_len - offset);

                json_array_get_str_len(&jobj, i, &len);
                offset += len;
                _mb_ctx.topic_list.topic_list[offset] = '\0';
                offset++;
            }
        }

        _mb_ctx.is_filled = true;
        VS_IOT_FREE(answer);
        VS_LOG_DEBUG("[MB] Credentials are loaded successfully");
        return VS_CODE_OK;
    }

clean:
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
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_cloud_message_bin_process(vs_clud_mb_process_topic_cb_t process_topic,
                             const char *root_ca_crt) {

    CHECK_NOT_ZERO_RET(_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(root_ca_crt, VS_CODE_ERR_NULLPTR_ARGUMENT);

    bool provision_is_present = _mb_ctx.is_filled || (VS_CODE_OK == _get_message_bin_credentials());

    if (provision_is_present) {
        if (!_mb_ctx.is_active) {

            VS_LOG_DEBUG("[MB]Connecting to broker host %s : %u ...", _mb_ctx.host, _mb_ctx.port);

            if (VS_CODE_OK == _impl->init(_mb_ctx.host,
                                        _mb_ctx.port,
                                        (const char *)_mb_ctx.cert,
                                        (const char *)_mb_ctx.pk,
                                        (const char *)root_ca_crt) &&
                VS_CODE_OK == _impl->connect_subscribe(_mb_ctx.client_id, _mb_ctx.login, _mb_ctx.password, &_mb_ctx.topic_list, process_topic)) {
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