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

#include "jsmn.h"
#include <virgil/iot/messenger/messenger.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/macros/macros.h>

#define ENCRYPTED_MESSAGE_SZ_MAX (4 * 1024)
#define DECRYPTED_MESSAGE_SZ_MAX (3 * 1024)

static const char *MESSENGER_CFG_SORAGE_ID = "MSGR_CFG_ID"; /**< Storage ID of Messenger's configuration for SecBox */
static const char *MESSENGER_USER_ID_TEMPLATE =
        "MSGR_%s_ID"; /**< Storage ID of Messenger's user credentials for SecBox */
static const char *MESSENGER_CHANNELS_SORAGE_ID_TEMPLATE =
        "MSGR_%s_CHAN_ID"; /**< Storage ID of Messenger's channels list for SecBox */

static vs_messenger_rx_cb_t _rx_cb = NULL;
static vs_messenger_config_t _config = {0, {0}, 0, {0}};
static vs_messenger_channels_t _user_channels = {0, {{0}}};
vs_messenger_virgil_user_creds_t _user_creds = {{0}, 0, {0}, 0, {0}};

// Forward declarations
static vs_status_e
_load_config(vs_messenger_config_t *config);

static vs_status_e
_load_user_channels(const char *identity, vs_messenger_channels_t *channels);

static vs_status_e
_load_user_cred(const char *identity, vs_messenger_virgil_user_creds_t *user_creds);

static vs_status_e
_save_user_cred(const char *identity, const vs_messenger_virgil_user_creds_t *user_creds);


#define MAXNUMBER_OF_TOKENS (32)
#define MAX_TOKEN_LENGTH (1024)

/******************************************************************************/
static void
_rx_encrypted_msg(const char *sender, const char *encrypted_message) {
    static uint8_t decrypted_message[DECRYPTED_MESSAGE_SZ_MAX];
    static size_t decrypted_message_sz = 0;
    int jsmn_res;
    jsmn_parser p;
    jsmntok_t tokens[MAXNUMBER_OF_TOKENS];
    char key_str[MAX_TOKEN_LENGTH] = {0};
    char prev_key_str[MAX_TOKEN_LENGTH] = {0};
    int i;
    char *json_msg = (char *)decrypted_message;
    bool done = false;

    if (!_rx_cb)
        return;

    // Decrypt message
    // DECRYPTED_MESSAGE_SZ_MAX - 1  - This is required for a Zero-terminated string
    if (VS_CODE_OK !=
        vs_messenger_virgil_decrypt_msg(
                sender, encrypted_message, decrypted_message, DECRYPTED_MESSAGE_SZ_MAX - 1, &decrypted_message_sz)) {
        VS_LOG_WARNING("Received message cannot be decrypted");
        return;
    }

    // Add Zero termination
    decrypted_message[decrypted_message_sz] = 0;

    // Get message from JSON
    jsmn_init(&p);
    jsmn_res = jsmn_parse(&p, json_msg, strnlen(json_msg, DECRYPTED_MESSAGE_SZ_MAX), tokens, MAXNUMBER_OF_TOKENS);

    if (jsmn_res <= 0) {
        VS_LOG_WARNING("Received message cannot be parsed");
        return;
    }

    for (i = 1; i <= jsmn_res - 1; i++) // jsmn_res == 0 => whole json string
    {
        jsmntok_t key = tokens[i];
        uint16_t length = key.end - key.start;

        if (length < MAX_TOKEN_LENGTH) {
            VS_IOT_MEMCPY(key_str, &json_msg[key.start], length);
            key_str[length] = '\0';

            if (0 == strcmp(prev_key_str, "body")) {
                strcpy(json_msg, key_str);
                done = true;
                break;
            }

            strcpy(prev_key_str, key_str);
        }
    }

    if (!done) {
        VS_LOG_WARNING("Received message does not contain correct body");
        return;
    }

    // Pass decrypted data for a processing
    _rx_cb(sender, (char *)decrypted_message);
}

/******************************************************************************/
vs_status_e
vs_messenger_start(const char *identity, vs_messenger_rx_cb_t rx_cb) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;
    char xmpp_pass[VS_MESSENGER_VIRGIL_TOKEN_SZ_MAX] = {0};

    // Check input parameters
    CHECK_NOT_ZERO(identity && identity[0]);

    // Save parameters
    _rx_cb = rx_cb;

    // Load connection configuration
    STATUS_CHECK(_load_config(&_config), "Cannot load Messenger configuration");

    // Load a list of available channels for User
    STATUS_CHECK(_load_user_channels(identity, &_user_channels), "Cannot load Messenger channels");

    // Initialize communication with Virgil Services
    STATUS_CHECK(vs_messenger_virgil_init(_config.messenger_base_url, NULL), "Cannot initialize Virgil SDK");

    // Try to load User's credentials
    if (VS_CODE_OK != _load_user_cred(identity, &_user_creds)) {
        VS_LOG_INFO("User %s is not registered. Sign up ...", identity);

        STATUS_CHECK(vs_messenger_virgil_sign_up(identity, &_user_creds), "Cannot Sign up User %s", identity);

        STATUS_CHECK(_save_user_cred(identity, &_user_creds), "Cannot Save credentials of User %s", identity);

    } else {
        VS_LOG_INFO("User %s is registered. Sign in ...", identity);
        STATUS_CHECK(vs_messenger_virgil_sign_in(&_user_creds), "Cannot Sign in User %s", identity);
    }

    // Get Enjabberd token from Virgil Messenger service and use it as XMPP password
    STATUS_CHECK(vs_messenger_virgil_get_xmpp_pass(xmpp_pass, VS_MESSENGER_VIRGIL_TOKEN_SZ_MAX),
                 "Cannot get XMPP password");

    // Open connection with Enjabberd
    STATUS_CHECK(vs_messenger_enjabberd_connect(
                         _config.enjabberd_host, _config.enjabberd_port, identity, xmpp_pass, _rx_encrypted_msg),
                 "Cannot connect to Enjabberd");

    res = VS_CODE_OK;
terminate:

    return res;
}

/******************************************************************************/
static char *
_fix_chars(char *str, char find, char replace) {
    char *current_pos = strchr(str, find);
    while (current_pos) {
        *current_pos = replace;
        current_pos = strchr(current_pos, find);
    }
    return str;
}

/******************************************************************************/
static char *
_fixed_str(const char *str) {
    char *res = NULL;
    if (!str) {
        return NULL;
    }
    res = strdup(str);
    return _fix_chars(res, '\n', ' ');
}

/******************************************************************************/
vs_status_e
vs_messenger_send(const char *recipient, const char *message) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;
    uint8_t encrypted_message[ENCRYPTED_MESSAGE_SZ_MAX];
    size_t encrypted_message_sz = 0;
    char *fixed_message = NULL;

    // Check input parameters
    CHECK_NOT_ZERO(recipient && recipient[0]);
    CHECK_NOT_ZERO(message && message[0]);

    fixed_message = _fixed_str(message);
    VS_LOG_DEBUG("Message to: %s  <%s>", recipient, fixed_message);

    // Create JSON-formatted message to be sent
    static const char json_tmpl[] = "{\"type\":\"text\",\"payload\":{\"body\":\"%s\"}}";
    char json_msg[DECRYPTED_MESSAGE_SZ_MAX];

    size_t req_sz = strlen(json_tmpl) + strlen(fixed_message);
    if (req_sz >= sizeof(json_msg)) {
        return VS_CODE_ERR_TOO_SMALL_BUFFER;
    }
    sprintf(json_msg, json_tmpl, fixed_message);

    // Encrypt message
    STATUS_CHECK(vs_messenger_virgil_encrypt_msg(
                         recipient, json_msg, encrypted_message, sizeof(encrypted_message), &encrypted_message_sz),
                 "Cannot encrypt message");

    // Send encrypted message
    STATUS_CHECK(vs_messenger_enjabberd_send(recipient, (char *)encrypted_message), "Cannot send XMPP message");

    res = VS_CODE_OK;

terminate:

    free(fixed_message);

    return res;
}

/******************************************************************************/
vs_status_e
vs_messenger_stop(void) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    STATUS_CHECK(vs_messenger_enjabberd_disconnect(), "Enjabberd disconnection error");
    STATUS_CHECK(vs_messenger_virgil_logout(), "Virgil Logout error");

terminate:
    res = VS_CODE_OK;
    return res;
}

/******************************************************************************/
static vs_status_e
_fill_storage_id(vs_storage_element_id_t *storage_element_id, const char *str_id, const char *identity) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;
    size_t requred_id_sz = 0;

    // Check input parameters
    CHECK_NOT_ZERO(storage_element_id);
    CHECK_NOT_ZERO(str_id);

    // Prepare storage id
    VS_IOT_MEMSET(storage_element_id, 0, sizeof(*storage_element_id));

    // Check if identity present
    if (identity) {
        requred_id_sz = strnlen(identity, VS_MESSENGER_VIRGIL_IDENTITY_SZ_MAX) + strlen(str_id);
        CHECK_RET(requred_id_sz <= VS_STORAGE_ELEMENT_ID_MAX, VS_CODE_ERR_INCORRECT_ARGUMENT, "Identity too big");
        sprintf((char *)storage_element_id, str_id, identity);
    } else {
        VS_IOT_MEMCPY(storage_element_id, str_id, strlen(str_id));
    }

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
static vs_status_e
_save_data(const uint8_t *data, size_t data_sz, const char *str_id, const char *identity) {
    vs_storage_element_id_t storage_element_id;
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(str_id && str_id[0]);
    CHECK_NOT_ZERO(data && data_sz);

    // Prepare storage id
    STATUS_CHECK(_fill_storage_id(&storage_element_id, str_id, identity), "");

    // Save configuration
    STATUS_CHECK(vs_secbox_save(VS_SECBOX_SIGNED_AND_ENCRYPTED, storage_element_id, data, data_sz),
                 "Cannot save Messenger data to SecBox");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
static vs_status_e
_load_data(const char *str_id, const char *identity, uint8_t *data, size_t data_sz) {
    vs_storage_element_id_t storage_element_id;
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(data && data_sz);

    // Prepare storage id
    STATUS_CHECK(_fill_storage_id(&storage_element_id, str_id, identity), "");

    // Save configuration
    STATUS_CHECK(vs_secbox_load(storage_element_id, data, data_sz), "Cannot load Messenger data from SecBox");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
static vs_status_e
_load_config(vs_messenger_config_t *config) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(config);

    // Save configuration
    STATUS_CHECK(_load_data(MESSENGER_CFG_SORAGE_ID, NULL, (uint8_t *)config, sizeof(*config)),
                 "Cannot load Messenger configuration from SecBox");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
static vs_status_e
_load_user_channels(const char *identity, vs_messenger_channels_t *channels) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(identity && identity[0]);
    CHECK_NOT_ZERO(channels);

    // Save configuration
    STATUS_CHECK(_load_data(MESSENGER_CHANNELS_SORAGE_ID_TEMPLATE, identity, (uint8_t *)channels, sizeof(*channels)),
                 "Cannot load Messenger channels from SecBox");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
static vs_status_e
_load_user_cred(const char *identity, vs_messenger_virgil_user_creds_t *user_creds) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(identity && identity[0]);
    CHECK_NOT_ZERO(user_creds);

    // Save configuration
    STATUS_CHECK(_load_data(MESSENGER_USER_ID_TEMPLATE, identity, (uint8_t *)user_creds, sizeof(*user_creds)),
                 "Cannot load User's credentials from SecBox");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
static vs_status_e
_save_user_cred(const char *identity, const vs_messenger_virgil_user_creds_t *user_creds) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(identity && identity[0]);
    CHECK_NOT_ZERO(user_creds);

    // Save configuration
    STATUS_CHECK(_save_data((const uint8_t *)user_creds, sizeof(*user_creds), MESSENGER_USER_ID_TEMPLATE, identity),
                 "Cannot save User's credentials to SecBox");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
vs_status_e
vs_messenger_configure(const vs_messenger_config_t *config) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(config);
    CHECK_NOT_ZERO(config->enjabberd_host);
    CHECK_NOT_ZERO(config->messenger_base_url);
    CHECK_RET(VS_MESSENGER_CFG_VERSION == config->version, VS_CODE_ERR_MSGR_VERSION, "Wrong version of configuration");

    // Save configuration
    STATUS_CHECK(_save_data((const uint8_t *)config, sizeof(*config), MESSENGER_CFG_SORAGE_ID, NULL),
                 "Cannot save Messenger configuration to SecBox");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
vs_status_e
vs_messenger_set_channels(const char *identity, const vs_messenger_channels_t *channels) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(channels);
    CHECK(channels->channels_num <= VS_MESSENGER_CHANNEL_MAX_SZ, "Not supported amount of Messenger's channels");

    // Save configuration
    STATUS_CHECK(
            _save_data((const uint8_t *)channels, sizeof(*channels), MESSENGER_CHANNELS_SORAGE_ID_TEMPLATE, identity),
            "Cannot save Messenger channels to SecBox");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
const char *
vs_messenger_default_channel(void) {
    if (_user_channels.channels_num) {
        return (char *)_user_channels.channel[0];
    }

    return NULL;
}

/******************************************************************************/
