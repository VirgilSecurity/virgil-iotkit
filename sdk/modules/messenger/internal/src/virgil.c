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

#include <virgil/iot/messenger/internal/virgil.h>

#include "private/visibility.h"

#include <virgil/crypto/common/vsc_common_public.h>
#include <virgil/crypto/common/private/vsc_str_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_foundation_public.h>
#include <virgil/crypto/pythia/vscp_pythia_public.h>

#include <virgil/sdk/core/vssc_core_sdk_public.h>
#include <virgil/sdk/core/private/vssc_core_sdk_private.h>
#include <virgil/sdk/pythia/vssp_pythia_sdk_public.h>
#include <virgil/sdk/keyknox/vssk_keyknox_sdk_public.h>

#include <locale.h>

// Limits
#define VS_VIRGIL_MESSENGER_ENC_DATA_MAX_SZ (4 * 1024) /**< Maximum size of encrypted data */

typedef struct {
    vscf_impl_t *private_key;
    vscf_impl_t *public_key;
    vsc_buffer_t *public_key_id;
    vsc_str_mutable_t card_id;
    bool is_ready;
} vs_messenger_inner_creds_t;

typedef struct {
    vscf_impl_t *rng;
    vsc_str_mutable_t base_url;
    vsc_str_mutable_t ca_bundle;
    vssc_key_handler_list_t *public_key_cache;
    bool is_initialized;
} vs_messenger_inner_config_t;

// Endpoints
// Brain Key configuration
#define MAKE_STR_CONSTANT(name, value)                                                                                 \
    static const char name##_CHARS[] = value;                                                                          \
    static const vsc_str_t name = {name##_CHARS, sizeof(name##_CHARS) - 1};

#define MAKE_DATA_CONSTANT_FROM_STR(name, value)                                                                       \
    static const byte name##_BYTES[] = value;                                                                          \
    static const vsc_data_t name = {name##_BYTES, sizeof(name##_BYTES) - 1};


MAKE_STR_CONSTANT(k_url_path_VIRGIL_JWT, "/virgil-jwt")
MAKE_STR_CONSTANT(k_url_path_EJABBERD_JWT, "/ejabberd-jwt")
MAKE_STR_CONSTANT(k_url_path_SIGNUP, "/signup")
MAKE_STR_CONSTANT(k_json_key_TOKEN, "token")
MAKE_STR_CONSTANT(k_json_key_RAW_CARD, "raw_card")
MAKE_STR_CONSTANT(k_json_key_VIRGIL_CARD, "virgil_card")
MAKE_STR_CONSTANT(k_json_key_CIPHERTEXT, "ciphertext")
MAKE_STR_CONSTANT(k_json_key_DATE, "date")
MAKE_STR_CONSTANT(k_json_key_VERSION, "version")
MAKE_STR_CONSTANT(k_json_value_V2, "v2")

MAKE_STR_CONSTANT(k_auth_JWT_PREFIX, "Bearer ")
MAKE_STR_CONSTANT(k_auth_HEDAER_NAME, "Authorization")


MAKE_DATA_CONSTANT_FROM_STR(k_brain_key_RECIPIENT_ID, "brain_key")

MAKE_STR_CONSTANT(k_brain_key_JSON_VERSION, "version")
MAKE_STR_CONSTANT(k_brain_key_JSON_CARD_ID, "card_id")
MAKE_STR_CONSTANT(k_brain_key_JSON_PRIVATE_KEY, "private_key")
MAKE_STR_CONSTANT(k_brain_key_JSON_PUBLIC_KEY, "public_key")
MAKE_STR_CONSTANT(k_brain_key_JSON_PUBLIC_KEY_ID, "public_key_id")

MAKE_STR_CONSTANT(k_keyknox_root_MESSENGER, "messenger")
MAKE_STR_CONSTANT(k_keyknox_path_CREDENTIALS, "credentials")

//
// Module global variables.
//
static vs_messenger_inner_config_t _config;
static vs_messenger_inner_creds_t _inner_creds;
static vssc_jwt_t *_jwt;

/******************************************************************************/
static void
_release_config(void) {
    vscf_impl_destroy(&_config.rng);
    vsc_str_mutable_release(&_config.base_url);
    vsc_str_mutable_release(&_config.ca_bundle);
    vssc_key_handler_list_destroy(&_config.public_key_cache);
    _config.is_initialized = false;
}

/******************************************************************************/
static void
_save_config(const char *base_url, const char *ca_bundle, vscf_ctr_drbg_t **ctr_drbg_ref) {

    VS_IOT_ASSERT(ctr_drbg_ref != NULL);
    VS_IOT_ASSERT(*ctr_drbg_ref != NULL);

    _config.base_url = vsc_str_mutable_from_str(vsc_str_from_str(base_url));

    if (ca_bundle && ca_bundle[0]) {
        VS_LOG_INFO("Set custom CA: %s", ca_bundle);
        _config.ca_bundle = vsc_str_mutable_from_str(vsc_str_from_str(ca_bundle));
    } else {
        _config.ca_bundle = vsc_str_mutable_from_str(vsc_str_empty());
    }

    _config.rng = vscf_ctr_drbg_impl(*ctr_drbg_ref);
    *ctr_drbg_ref = NULL;

    _config.public_key_cache = vssc_key_handler_list_new();

    _config.is_initialized = true;
}

/******************************************************************************/
static void
_release_inner_creds(void) {

    vsc_buffer_destroy(&_inner_creds.public_key_id);
    vscf_impl_destroy(&_inner_creds.public_key);
    vscf_impl_destroy(&_inner_creds.private_key);
    vsc_str_mutable_release(&_inner_creds.card_id);
    _inner_creds.is_ready = false;
}

/******************************************************************************/
static void
_store_inner_creds(vsc_str_t card_id,
                   vsc_buffer_t **public_key_id_ref,
                   vscf_impl_t **public_key_ref,
                   vscf_impl_t **private_key_ref) {

    VS_IOT_ASSERT(vsc_str_is_valid_and_non_empty(card_id));
    VS_IOT_ASSERT(public_key_id_ref != NULL);
    VS_IOT_ASSERT(*public_key_id_ref != NULL);
    VS_IOT_ASSERT(public_key_ref != NULL);
    VS_IOT_ASSERT(*public_key_ref != NULL);
    VS_IOT_ASSERT(private_key_ref != NULL);
    VS_IOT_ASSERT(*private_key_ref != NULL);

    _release_inner_creds();

    _inner_creds.card_id = vsc_str_mutable_from_str(card_id);

    _inner_creds.public_key_id = *public_key_id_ref;
    *public_key_id_ref = NULL;

    _inner_creds.public_key = *public_key_ref;
    *public_key_ref = NULL;

    _inner_creds.private_key = *private_key_ref;
    *private_key_ref = NULL;

    _inner_creds.is_ready = true;
}

/******************************************************************************/
static vsc_str_t
_base_url(void) {
    VS_IOT_ASSERT(_config.is_initialized);

    return vsc_str_mutable_as_str(_config.base_url);
}

static vsc_str_t
_ca_bundle(void) {
    VS_IOT_ASSERT(_config.is_initialized);

    return vsc_str_mutable_as_str(_config.ca_bundle);
}

/******************************************************************************/
static vs_status_e
_request_messenger_token(vsc_str_t endpoint, char *token, size_t token_buf_sz) {
    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(_config.is_initialized);
    VS_IOT_ASSERT(_inner_creds.is_ready);

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(vsc_str_is_valid_and_non_empty(endpoint), VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(token, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(token_buf_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    //  Declare resources.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vsc_buffer_t *jwt_signature = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vsc_str_mutable_t auth_url = {NULL, 0};
    vsc_str_mutable_t auth_header = {NULL, 0};
    vssc_json_object_t *token_json = NULL;

    //
    //  Create messenger JWT.
    //
    vs_status_e status = VS_CODE_ERR_MSGR_CRYPTO;

    vscf_signer_t *signer = vscf_signer_new();
    vscf_signer_use_random(signer, _config.rng);
    vscf_signer_take_hash(signer, vscf_sha512_impl(vscf_sha512_new()));
    const size_t jwt_signature_len = vscf_signer_signature_len(signer, _inner_creds.private_key);

    vsc_str_t card_id = vsc_str_mutable_as_str(_inner_creds.card_id);

    char timestamp_str[22] = {'\0'};
    snprintf(timestamp_str, sizeof(timestamp_str) - 1, "%lu", vssc_unix_time_now());
    vsc_str_t timestamp = vsc_str_from_str(timestamp_str);

    const size_t jwt_signature_str_len = vscf_base64_encoded_len(jwt_signature_len);
    const size_t jwt_to_sign_len = card_id.len + 1 /* dot */ + timestamp.len;
    const size_t jwt_len = jwt_to_sign_len + 1 /* dot */ + jwt_signature_str_len;

    vsc_str_buffer_t *jwt = vsc_str_buffer_new_with_capacity(jwt_len);
    vsc_str_buffer_append_str(jwt, card_id);
    vsc_str_buffer_append_char(jwt, '.');
    vsc_str_buffer_append_str(jwt, timestamp);

    jwt_signature = vsc_buffer_new_with_capacity(jwt_signature_len);
    vscf_signer_reset(signer);
    vscf_signer_append_data(signer, vsc_str_as_data(vsc_str_buffer_str(jwt)));
    const vscf_status_t sign_status = vscf_signer_sign(signer, _inner_creds.private_key, jwt_signature);
    CHECK(sign_status == vscf_status_SUCCESS, "Failed to sign JWT");

    vsc_str_buffer_append_char(jwt, '.');
    vscf_base64_encode(vsc_buffer_data(jwt_signature), &(jwt->buffer));

    auth_header = vsc_str_mutable_concat(k_auth_JWT_PREFIX, vsc_str_buffer_str(jwt));

    vsc_str_buffer_destroy(&jwt);

    //
    //  Perform auth and get Virgil or Ejabberd JWT depends on the given endpoint.
    //
    status = VS_CODE_ERR_MSGR_SERVICE;

    auth_url = vsc_str_mutable_concat(_base_url(), endpoint);
    http_request = vssc_http_request_new_with_url(vssc_http_request_method_get, vsc_str_mutable_as_str(auth_url));

    vssc_http_request_add_header(http_request, k_auth_HEDAER_NAME, vsc_str_mutable_as_str(auth_header));
    vsc_str_mutable_release(&auth_header);

    http_response = vssc_virgil_http_client_send_custom_with_ca(http_request, _ca_bundle(), &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error),
          "Failed to get JWT from the endpoint: %s (cannot send request)",
          auth_url.chars);

    CHECK(vssc_http_response_is_success(http_response),
          "Failed to get JWT from the endpoint: %s (errored response)",
          auth_url.chars);

    token_json = vssc_json_object_parse(vssc_http_response_body(http_response), &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse JWT from the endpoint: %s", auth_url.chars);

    vsc_str_t token_str = vssc_json_object_get_string_value(token_json, k_json_key_TOKEN, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse JWT from the endpoint: %s", auth_url.chars);

    status = VS_CODE_ERR_MSGR_INTERNAL;

    CHECK(token_str.len < token_buf_sz, "Failed to parse JWT (token buffer too small)");
    strcpy(token, token_str.chars);

    // Print results
    VS_LOG_DEBUG("Token from %s : %s", auth_url.chars, token);

    status = VS_CODE_OK;

terminate:

    vsc_buffer_destroy(&jwt_signature);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vsc_str_mutable_release(&auth_url);
    vsc_str_mutable_release(&auth_header);
    vssc_json_object_destroy(&token_json);

    return status;
}

/******************************************************************************/
static vs_status_e
_update_virgil_jwt(void) {
    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(_inner_creds.private_key != NULL);
    VS_IOT_ASSERT(_inner_creds.public_key != NULL);

    //
    //  Request a new Virgil JWT.
    //
    char messenger_token[VS_MESSENGER_VIRGIL_TOKEN_SZ_MAX] = {'\0'};

    const vs_status_e messenger_token_status =
            _request_messenger_token(k_url_path_VIRGIL_JWT, messenger_token, sizeof(messenger_token));

    CHECK_RET(messenger_token_status == VS_CODE_OK,
              VS_CODE_ERR_MSGR_UPD_TOKEN,
              "Failed to get a new Virgil JWT (service error)");

    //
    //  Parse Virgil JWT.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vsc_str_t jwt_str = vsc_str_from_str(messenger_token);
    vssc_jwt_t *jwt = vssc_jwt_parse(jwt_str, &core_sdk_error);
    CHECK_RET(!vssc_error_has_error(&core_sdk_error),
              VS_CODE_ERR_MSGR_UPD_TOKEN,
              "Failed to get a new Virgil JWT (parse error)");

    //
    //  Update Virgil JWT within creds.
    //
    vssc_jwt_destroy(&_jwt);

    _jwt = jwt;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_update_virgil_jwt_if_expired(void) {
    VS_IOT_ASSERT(_config.is_initialized);
    VS_IOT_ASSERT(_inner_creds.is_ready);

    if (_jwt != NULL && !vssc_jwt_is_expired(_jwt)) {
        return VS_CODE_OK;
    }

    return _update_virgil_jwt();
}

/******************************************************************************/
static vs_status_e
_import_user_creds(const vs_messenger_virgil_user_creds_t *creds) {
    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(_config.is_initialized);

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(creds, VS_CODE_ERR_MSGR_INTERNAL);
    CHECK_NOT_ZERO_RET(creds->pubkey_sz, VS_CODE_ERR_MSGR_INTERNAL);
    CHECK_NOT_ZERO_RET(creds->privkey_sz, VS_CODE_ERR_MSGR_INTERNAL);
    CHECK_NOT_ZERO_RET(creds->card_id, VS_CODE_ERR_MSGR_INTERNAL);
    CHECK_NOT_ZERO_RET(creds->card_id[0], VS_CODE_ERR_MSGR_INTERNAL);

    //
    //  Cleanup previous inner creds.
    //
    _release_inner_creds();

    //
    //  Import given creds to the inner creds.
    //
    vs_status_e status = VS_CODE_ERR_MSGR_CRYPTO;

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, _config.rng);

    vsc_data_t private_key_data = vsc_data(creds->privkey, creds->privkey_sz);
    _inner_creds.private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &foundation_error);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to import private key from the given credentials");

    vsc_data_t public_key_data = vsc_data(creds->pubkey, creds->pubkey_sz);
    _inner_creds.public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &foundation_error);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to import public key from the given credentials");

    vsc_data_t public_key_id = vsc_data(creds->pubkey_id, VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ);
    _inner_creds.public_key_id = vsc_buffer_new_with_data(public_key_id);

    _inner_creds.card_id = vsc_str_mutable_from_str(vsc_str_from_str(creds->card_id));

    _inner_creds.is_ready = true;

    status = VS_CODE_OK;

terminate:

    vscf_key_provider_destroy(&key_provider);

    if (status != VS_CODE_OK) {
        _release_inner_creds();
    }

    return status;
}


/******************************************************************************/
static vs_status_e
_export_user_creds(vs_messenger_virgil_user_creds_t *creds) {
    //
    //  Check input parameters.
    //
    VS_IOT_ASSERT(_config.is_initialized);
    VS_IOT_ASSERT(_inner_creds.is_ready);

    //
    //  Prepare vars.
    //
    vsc_buffer_t *export_buffer = vsc_buffer_new();

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, _config.rng);

    vs_status_e status = VS_CODE_ERR_MSGR_INTERNAL;
    vscf_status_t foundation_status = vscf_status_SUCCESS;

    //
    //  Cleanup creds.
    //
    vsc_zeroize(creds, sizeof(vs_messenger_virgil_user_creds_t));

    //
    //  Store Public Key data.
    //
    CHECK(vscf_key_provider_exported_public_key_len(key_provider, _inner_creds.public_key) <=
                  VS_MESSENGER_VIRGIL_KEY_SZ_MAX,
          "Failed to register a new Card (wrong size of exported public key)");

    vsc_buffer_release(export_buffer);
    vsc_buffer_use(export_buffer, creds->pubkey, VS_MESSENGER_VIRGIL_KEY_SZ_MAX);

    foundation_status = vscf_key_provider_export_public_key(key_provider, _inner_creds.public_key, export_buffer);
    if (foundation_status != vscf_status_SUCCESS) {
        status = VS_CODE_ERR_CRYPTO;
        VS_LOG_ERROR("Failed to register a new Card (cannot export public key data)");
        goto terminate;
    }

    creds->pubkey_sz = vsc_buffer_len(export_buffer);

    //
    //  Store Public Key identifier.
    //
    CHECK(vsc_buffer_len(_inner_creds.public_key_id) == VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ,
          "Wrong size of public key id");
    VS_IOT_MEMCPY(
            creds->pubkey_id, vsc_buffer_bytes(_inner_creds.public_key_id), vsc_buffer_len(_inner_creds.public_key_id));

    //
    //  Store Private Key data.
    //
    CHECK(vscf_key_provider_exported_private_key_len(key_provider, _inner_creds.private_key) <=
                  VS_MESSENGER_VIRGIL_KEY_SZ_MAX,
          "Failed to register a new Card (wrong size of exported private key)");

    vsc_buffer_release(export_buffer);
    vsc_buffer_use(export_buffer, creds->privkey, VS_MESSENGER_VIRGIL_KEY_SZ_MAX);

    foundation_status = vscf_key_provider_export_private_key(key_provider, _inner_creds.private_key, export_buffer);
    if (foundation_status != vscf_status_SUCCESS) {
        status = VS_CODE_ERR_CRYPTO;
        VS_LOG_ERROR("Failed to register a new Card (cannot export private key data)");
        goto terminate;
    }

    creds->privkey_sz = vsc_buffer_len(export_buffer);

    //
    //  Store Card identifier.
    //
    vsc_str_t card_id = vsc_str_mutable_as_str(_inner_creds.card_id);
    CHECK(card_id.len < VS_MESSENGER_VIRGIL_CARD_ID_SZ_MAX, "Failed to register a new Card (wrong size of card id)");

    VS_IOT_MEMCPY(creds->card_id, card_id.chars, card_id.len);
    creds->card_id[card_id.len] = '\0';

    status = VS_CODE_OK;

terminate:

    if (status != VS_CODE_OK) {
        vsc_zeroize(creds, sizeof(vs_messenger_virgil_user_creds_t));
    }

    vscf_key_provider_destroy(&key_provider);
    vsc_buffer_destroy(&export_buffer);

    return status;
}

/******************************************************************************/
static void
_log_user_creds(const vs_messenger_virgil_user_creds_t *creds) {
    VS_IOT_ASSERT(creds != NULL);

    vsc_data_t public_key_id = vsc_data(creds->pubkey_id, VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ);
    vsc_data_t public_key_data = vsc_data(creds->pubkey, creds->pubkey_sz);
    vsc_data_t private_key_data = vsc_data(creds->privkey, creds->privkey_sz);

    vsc_str_buffer_t *hex_buf = vsc_str_buffer_new();

    vsc_str_buffer_reset_with_capacity(hex_buf, vscf_binary_to_hex_len(public_key_data.len) + 1);
    vscf_binary_to_hex(public_key_data, hex_buf);
    vsc_str_buffer_make_null_terminated(hex_buf);
    VS_LOG_DEBUG("Public key    : %s", vsc_str_buffer_chars(hex_buf));

    vsc_str_buffer_reset_with_capacity(hex_buf, vscf_binary_to_hex_len(private_key_data.len) + 1);
    vscf_binary_to_hex(private_key_data, hex_buf);
    vsc_str_buffer_make_null_terminated(hex_buf);
    VS_LOG_DEBUG("Private key   : %s", vsc_str_buffer_chars(hex_buf));

    VS_LOG_DEBUG("Card ID       : %s", creds->card_id);

    vsc_str_buffer_reset_with_capacity(hex_buf, vscf_binary_to_hex_len(public_key_id.len) + 1);
    vscf_binary_to_hex(public_key_id, hex_buf);
    vsc_str_buffer_make_null_terminated(hex_buf);
    VS_LOG_DEBUG("Public key ID : %s", vsc_str_buffer_chars(hex_buf));

    vsc_str_buffer_destroy(&hex_buf);
}

/******************************************************************************/
static vs_status_e
_generate_brain_key(const char *pwd, const vssc_jwt_t *jwt, vscf_impl_t **private_key, vscf_impl_t **public_key) {
    //
    //  Declare resources.
    //
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssp_error_t pythia_sdk_error;
    vssp_error_reset(&pythia_sdk_error);

    vscf_key_material_rng_t *key_material_rng = NULL;
    vscf_key_provider_t *key_provider = NULL;

    vscp_status_t pythia_status = vscp_status_SUCCESS;
    vssp_pythia_client_t *pythia_client = NULL;
    vssp_brain_key_seed_t *seed = NULL;

    vssc_http_request_t *http_request = NULL;
    vssc_virgil_http_response_t *http_response = NULL;

    vsc_buffer_t *blinded_password = NULL;
    vsc_buffer_t *blinding_secret = NULL;
    vsc_buffer_t *deblinded_password = NULL;

    //
    //  Blind.
    //
    blinded_password = vsc_buffer_new_with_capacity(vscp_pythia_blinded_password_buf_len());

    blinding_secret = vsc_buffer_new_with_capacity(vscp_pythia_blinding_secret_buf_len());

    pythia_status = vscp_pythia_blind(vsc_str_as_data(vsc_str_from_str(pwd)), blinded_password, blinding_secret);
    CHECK(pythia_status == vscp_status_SUCCESS, "Failed to blind password");

    //
    //  Get seed.
    //
    pythia_client = vssp_pythia_client_new();

    http_request = vssp_pythia_client_make_request_generate_seed(pythia_client, vsc_buffer_data(blinded_password));

    vsc_buffer_destroy(&blinded_password);

    http_response = vssc_virgil_http_client_send(http_request, jwt, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to generate brain key seed");

    seed = vssp_pythia_client_process_response_generate_seed(http_response, &pythia_sdk_error);
    CHECK(!vssp_error_has_error(&pythia_sdk_error), "Failed to generate brain key seed");

    vssc_http_request_destroy(&http_request);
    vssc_virgil_http_response_destroy(&http_response);

    deblinded_password = vsc_buffer_new_with_capacity(vscp_pythia_deblinded_password_buf_len());

    pythia_status =
            vscp_pythia_deblind(vssp_brain_key_seed_get(seed), vsc_buffer_data(blinding_secret), deblinded_password);

    CHECK(pythia_status == vscp_status_SUCCESS, "Failed to deblind password");

    vsc_buffer_destroy(&blinding_secret);

    //
    // Generate key.
    //
    key_material_rng = vscf_key_material_rng_new();

    vscf_key_material_rng_reset_key_material(key_material_rng, vsc_buffer_data(deblinded_password));

    vsc_buffer_destroy(&deblinded_password);

    key_provider = vscf_key_provider_new();

    vscf_key_provider_use_random(key_provider, vscf_key_material_rng_impl(key_material_rng));

    *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, NULL);
    CHECK(*private_key != NULL, "Failed to generate brain key");

    *public_key = vscf_private_key_extract_public_key(*private_key);

    res = VS_CODE_OK;

terminate:
    vscf_key_material_rng_destroy(&key_material_rng);
    vscf_key_provider_destroy(&key_provider);
    vssp_pythia_client_destroy(&pythia_client);
    vssp_brain_key_seed_destroy(&seed);
    vssc_http_request_destroy(&http_request);
    vssc_virgil_http_response_destroy(&http_response);
    vsc_buffer_destroy(&blinded_password);
    vsc_buffer_destroy(&blinding_secret);
    vsc_buffer_destroy(&deblinded_password);

    return res;
}

/******************************************************************************/
static vs_status_e
_get_public_key_by_identity(vsc_str_t identity, const vssc_key_handler_t **key_handler_ref) {
    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(_config.is_initialized);
    VS_IOT_ASSERT(_inner_creds.is_ready);

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(vsc_str_is_valid_and_non_empty(identity), VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(key_handler_ref, VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    //  Find within local cache.
    //
    const vssc_key_handler_t *cached_key_handler =
            vssc_key_handler_list_find_with_identity(_config.public_key_cache, identity, NULL);
    if (cached_key_handler != NULL) {
        *key_handler_ref = cached_key_handler;
        return VS_CODE_OK;
    }

    //
    //  There is no cached public key, let's get it from the Cloud.
    //
    //  Update Virgil JWT first.
    //
    const vs_status_e update_jwt_status = _update_virgil_jwt_if_expired();
    CHECK_RET(update_jwt_status == VS_CODE_OK, update_jwt_status, "Failed to get card (cannot update Virgil JWT)");

    //
    // Declare vars.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_card_manager_t *card_manager = NULL;
    vssc_card_client_t *card_client = NULL;
    vssc_http_request_t *search_cards_request = NULL;
    vssc_virgil_http_response_t *search_cards_response = NULL;
    vssc_raw_card_list_t *found_raw_cards = NULL;
    vssc_card_t *found_card = NULL;
    vssc_key_handler_t *key_handler = NULL;

    //
    //  Configure algorithms.
    //
    vs_status_e status = VS_CODE_ERR_CRYPTO;

    card_manager = vssc_card_manager_new();
    vssc_card_manager_use_random(card_manager, _config.rng);
    core_sdk_error.status = vssc_card_manager_configure(card_manager);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to get card (failed init crypto module)");

    //
    //  Send request.
    //
    status = VS_CODE_ERR_MSGR_SERVICE;

    card_client = vssc_card_client_new();

    search_cards_request = vssc_card_client_make_request_search_cards_with_identity(card_client, identity);

    search_cards_response =
            vssc_virgil_http_client_send_with_ca(search_cards_request, _jwt, _ca_bundle(), &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to get card (cannot send request)");

    if (!vssc_virgil_http_response_is_success(search_cards_response)) {
        VS_LOG_ERROR("Failed to get card (errored response)");
        VS_LOG_ERROR("    http status code: %lu", vssc_virgil_http_response_status_code(search_cards_response));

        if (vssc_virgil_http_response_has_service_error(search_cards_response)) {
            VS_LOG_ERROR("    virgil error: %lu %s",
                         vssc_virgil_http_response_service_error_code(search_cards_response),
                         vssc_virgil_http_response_service_error_description(search_cards_response));
        }

        goto terminate;
    }


    found_raw_cards = vssc_card_client_process_response_search_cards(search_cards_response, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to get card (failed to parse response)");
    CHECK(vssc_raw_card_list_has_item(found_raw_cards), "Failed to get card (not found)");

    found_card =
            vssc_card_manager_import_raw_card(card_manager, vssc_raw_card_list_item(found_raw_cards), &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to get card (failed to import raw card)");

    key_handler =
            vssc_key_handler_new_with(identity, vssc_card_public_key_id(found_card), vssc_card_public_key(found_card));

    *key_handler_ref = key_handler;

    vssc_key_handler_list_add(_config.public_key_cache, &key_handler);

    status = VS_CODE_OK;

terminate:

    vssc_card_manager_destroy(&card_manager);
    vssc_card_client_destroy(&card_client);
    vssc_http_request_destroy(&search_cards_request);
    vssc_virgil_http_response_destroy(&search_cards_response);
    vssc_raw_card_list_destroy(&found_raw_cards);
    vssc_card_destroy(&found_card);

    return status;
}


/******************************************************************************/
DLL_PUBLIC bool
vs_messenger_virgil_is_init(void) {
    return _config.is_initialized;
}

/******************************************************************************/
DLL_PUBLIC bool
vs_messenger_virgil_is_signed_in(void) {
    return _config.is_initialized && _inner_creds.is_ready;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_virgil_init(const char *service_base_url, const char *custom_ca) {
    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(service_base_url && service_base_url[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    //  Re-entrance check.
    //
    if (_config.is_initialized) {
        VS_LOG_WARNING("Virgil Messenger is initialized");
        return VS_CODE_ERR_MSGR_INTERNAL;
    }

    //
    //  Configure logger.
    //
    //  FIXME: Change it for production.
    setlocale(LC_NUMERIC, "C");
    vs_logger_init(VS_LOGLEV_DEBUG);

    //
    //  Configure heavy crypto modules.
    //
    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();
    const vscf_status_t rng_status = vscf_ctr_drbg_setup_defaults(ctr_drbg);
    if (rng_status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&ctr_drbg);
        VS_LOG_ERROR("Cannot initialize 'Random' crypto module");
        return VS_CODE_ERR_MSGR_CRYPTO;
    }

    const vscp_status_t pythia_status = vscp_pythia_configure();
    if (pythia_status != vscp_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&ctr_drbg);
        VS_LOG_ERROR("Cannot initialize 'Pythia' crypto library");
        return VS_CODE_ERR_MSGR_CRYPTO;
    }

    //
    //  Save configuration.
    //
    _save_config(service_base_url, custom_ca, &ctr_drbg);

    return VS_CODE_OK;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_virgil_sign_in(const vs_messenger_virgil_user_creds_t *creds) {
    VS_IOT_ASSERT(_config.is_initialized);

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(creds, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->pubkey_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->privkey_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->card_id[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    //  Import creds.
    //
    const vs_status_e import_creds_status = _import_user_creds(creds);
    CHECK_RET(import_creds_status == VS_CODE_OK, import_creds_status, "Failed to import credentials");

    //
    //  Get a new Virgil JWT.
    //
    const vs_status_e update_jwt_status = _update_virgil_jwt();
    if (update_jwt_status != VS_CODE_OK) {
        _release_inner_creds();
        VS_LOG_ERROR("Failed to login (cannot refresh Virgil JWT)");
        return update_jwt_status;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_virgil_sign_up(const char *identity, vs_messenger_virgil_user_creds_t *creds) {

    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(_config.is_initialized);

    //
    // Check input parameters.
    //
    CHECK_NOT_ZERO_RET(identity && identity[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds, VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    // Clean destination data.
    //
    VS_IOT_MEMSET(creds, 0, sizeof(*creds));

    //
    //  Prepare vars and algorithms.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, _config.rng);

    vsc_str_mutable_t request_url = {NULL, 0};

    vscf_impl_t *card_private_key = NULL;
    vscf_impl_t *card_public_key = NULL;
    vsc_buffer_t *card_public_key_id = NULL;

    vssc_card_manager_t *card_manager = NULL;
    vssc_raw_card_t *initial_raw_card = NULL;
    vssc_raw_card_t *registered_raw_card = NULL;
    vssc_card_t *registered_card = NULL;

    vssc_json_object_t *initial_raw_card_json = NULL;
    vssc_json_object_t *register_raw_card_json = NULL;
    vssc_json_object_t *registered_raw_card_json = NULL;

    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssc_virgil_http_response_t *register_card_response = NULL;

    vs_status_e status = VS_CODE_ERR_MSGR_CRYPTO;

    //
    //  Generate Key Pair for a new Card.
    //
    card_private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &foundation_error);
    CHECK(!vscf_error_has_error(&foundation_error), "Filed to generate a new key for the Card");

    card_public_key = vscf_private_key_extract_public_key(card_private_key);

    card_public_key_id = vsc_buffer_new_with_capacity(vscf_key_provider_KEY_ID_LEN);

    foundation_error.status = vscf_key_provider_calculate_key_id(key_provider, card_public_key, card_public_key_id);
    CHECK(!vscf_error_has_error(&foundation_error), "Filed to calculate public key identifier");


    //
    //  Generate a new Raw Card.
    //
    card_manager = vssc_card_manager_new();
    vssc_card_manager_use_random(card_manager, _config.rng);
    core_sdk_error.status = vssc_card_manager_configure(card_manager);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to register a new Card (cannot configure card manager)");

    initial_raw_card = vssc_card_manager_generate_raw_card(
            card_manager, vsc_str_from_str(identity), card_private_key, &core_sdk_error);

    //
    //  Register a new Raw Card.
    //
    status = VS_CODE_ERR_MSGR_SERVICE;

    initial_raw_card_json = vssc_raw_card_export_as_json(initial_raw_card);

    register_raw_card_json = vssc_json_object_new();
    vssc_json_object_add_object_value(register_raw_card_json, k_json_key_RAW_CARD, initial_raw_card_json);

    request_url = vsc_str_mutable_concat(_base_url(), k_url_path_SIGNUP);

    http_request = vssc_http_request_new_with_body(vssc_http_request_method_post,
                                                   vsc_str_mutable_as_str(request_url),
                                                   vssc_json_object_as_str(register_raw_card_json));

    vssc_http_request_add_header(
            http_request, vssc_http_header_name_content_type, vssc_http_header_value_application_json);

    http_response = vssc_virgil_http_client_send_custom_with_ca(http_request, _ca_bundle(), &core_sdk_error);

    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to register a new Card (cannot send request)");

    register_card_response = vssc_virgil_http_response_create_from_http_response(http_response, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to register a new Card (cannot parse request)");

    if (!vssc_virgil_http_response_is_success(register_card_response)) {
        VS_LOG_ERROR("Failed to register a new Card (errored response)");
        VS_LOG_ERROR("    http status code: %lu", vssc_virgil_http_response_status_code(register_card_response));

        if (vssc_virgil_http_response_has_service_error(register_card_response)) {
            VS_LOG_ERROR("    virgil error: %lu %s",
                         vssc_virgil_http_response_service_error_code(register_card_response),
                         vssc_virgil_http_response_service_error_description(register_card_response));
        }

        goto terminate;
    }

    CHECK(vssc_virgil_http_response_body_is_json_object(register_card_response),
          "Failed to register a new Card (empty http body)");

    registered_raw_card_json =
            vssc_json_object_get_object_value(vssc_virgil_http_response_body_as_json_object(register_card_response),
                                              k_json_key_VIRGIL_CARD,
                                              &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to register a new Card (cannot parse)");

    registered_raw_card = vssc_raw_card_import_from_json(registered_raw_card_json, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to register a new Card (cannot parse)");

    //
    //  Import the registered Raw Card.
    //
    status = VS_CODE_ERR_MSGR_CRYPTO;

    registered_card = vssc_card_manager_import_raw_card_with_initial_raw_card(
            card_manager, registered_raw_card, initial_raw_card, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to register a new Card (cannot import)");

    //
    //  Store inner credentials.
    //
    _store_inner_creds(vssc_card_identifier(registered_card), &card_public_key_id, &card_public_key, &card_private_key);

    //
    //  Export user creds.
    //
    status = _export_user_creds(creds);
    CHECK(VS_CODE_OK == status, "Failed to signup (cannot export user credentials)");

    //
    //  Log user creds.
    //
    _log_user_creds(creds);

    //
    //  Get a new Virgil JWT.
    //
    status = _update_virgil_jwt();
    CHECK(VS_CODE_OK == status, "Failed to signup (cannot get a Virgil JWT)");

terminate:

    vsc_str_mutable_release(&request_url);
    vscf_impl_destroy(&card_private_key);
    vscf_impl_destroy(&card_public_key);
    vsc_buffer_destroy(&card_public_key_id);
    vssc_card_manager_destroy(&card_manager);
    vssc_raw_card_destroy(&initial_raw_card);
    vssc_raw_card_destroy(&registered_raw_card);
    vssc_card_destroy(&registered_card);
    vssc_json_object_destroy(&initial_raw_card_json);
    vssc_json_object_destroy(&register_raw_card_json);
    vssc_json_object_destroy(&registered_raw_card_json);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vssc_virgil_http_response_destroy(&register_card_response);

    if (status != VS_CODE_OK) {
        _release_inner_creds();
    }

    return status;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_virgil_get_xmpp_pass(char *pass, size_t pass_buf_sz) {
    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(vs_messenger_virgil_is_signed_in());

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(pass, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(pass_buf_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    return _request_messenger_token(k_url_path_EJABBERD_JWT, pass, pass_buf_sz);
}

/******************************************************************************/
DLL_PUBLIC void
vs_messenger_virgil_logout(void) {

    _release_inner_creds();

    _release_config();

    vssc_jwt_destroy(&_jwt);
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_virgil_decrypt_msg(const char *sender,
                                const char *encrypted_message,
                                uint8_t *decrypted_message,
                                size_t buf_sz,
                                size_t *decrypted_message_sz) {

    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(vs_messenger_virgil_is_signed_in());

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(sender && sender[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(decrypted_message, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(decrypted_message_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    // Get Sender's public key.
    //
    const vssc_key_handler_t *sender_key_handler = NULL;
    const vs_status_e search_status = _get_public_key_by_identity(vsc_str_from_str(sender), &sender_key_handler);
    CHECK_RET(search_status == VS_CODE_OK, search_status, "Failed to decrypt message (cannot get Sender's public key)");

    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vsc_buffer_t *ciphertext_json_str = NULL;
    vsc_buffer_t *ciphertext = NULL;
    vsc_buffer_t *plaintext = NULL;

    vssc_json_object_t *ciphertext_json = NULL;

    vscf_recipient_cipher_t *recipient_cipher = NULL;

    vs_status_e status = VS_CODE_ERR_CRYPTO;

    //
    //  Unpack ciphertext to base64({"ciphertext":"BASE64=","version":"v2"}).
    //
    vsc_data_t encrypted_message_data = vsc_str_as_data(vsc_str_from_str(encrypted_message));
    ciphertext_json_str = vsc_buffer_new_with_capacity(vscf_base64_decoded_len(encrypted_message_data.len));
    foundation_error.status = vscf_base64_decode(encrypted_message_data, ciphertext_json_str);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to to decrypt message (input message is not base64)");

    ciphertext_json = vssc_json_object_parse(vsc_str_from_data(vsc_buffer_data(ciphertext_json_str)), &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to to decrypt message (input message is not base64(json))");

    ciphertext = vssc_json_object_get_binary_value_new(ciphertext_json, k_json_key_CIPHERTEXT, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error),
          "Failed to to decrypt message (decoded encrypted message has no JSON key 'ciphertext')");


    //
    //  Decrypt message.
    //
    recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, _config.rng);

    foundation_error.status = vscf_recipient_cipher_start_decryption_with_key(
            recipient_cipher, vsc_buffer_data(_inner_creds.public_key_id), _inner_creds.private_key, vsc_data_empty());

    CHECK(!vscf_error_has_error(&foundation_error), "Failed to to decrypt message (start decryption failed)");


    const size_t plaintext_len =
            vscf_recipient_cipher_decryption_out_len(recipient_cipher, vsc_buffer_len(ciphertext)) +
            vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0);

    CHECK(plaintext_len <= buf_sz, "Failed to to decrypt message (output buffer too small)");

    plaintext = vsc_buffer_new();
    vsc_buffer_use(plaintext, decrypted_message, buf_sz);

    foundation_error.status =
            vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(ciphertext), plaintext);

    CHECK(!vscf_error_has_error(&foundation_error), "Failed to to decrypt message");

    foundation_error.status = vscf_recipient_cipher_finish_decryption(recipient_cipher, plaintext);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to to decrypt message");

    //
    //  Verify.
    //
    CHECK(vscf_recipient_cipher_is_data_signed(recipient_cipher), "Failed to to decrypt message (no signature)");
    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(recipient_cipher);

    CHECK(vscf_signer_info_list_has_item(signer_infos), "Failed to to decrypt message (no signature)");
    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);

    const bool verified = vscf_recipient_cipher_verify_signer_info(
            recipient_cipher, signer_info, vssc_key_handler_key(sender_key_handler));
    CHECK(verified, "Failed to to decrypt message (signature verification failed)");

    *decrypted_message_sz = vsc_buffer_len(plaintext);

    status = VS_CODE_OK;

terminate:

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&ciphertext_json_str);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&plaintext);
    vssc_json_object_destroy(&ciphertext_json);
    vscf_recipient_cipher_destroy(&recipient_cipher);

    return status;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_virgil_encrypt_msg(const char *recipient,
                                const char *message,
                                uint8_t *encrypted_message,
                                size_t buf_sz,
                                size_t *encrypted_message_sz) {

    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(vs_messenger_virgil_is_signed_in());

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(recipient && recipient[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(message && message[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(encrypted_message, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(encrypted_message_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf_sz > 0, VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    // Get Sender's public key.
    //
    const vssc_key_handler_t *recipient_key_handler = NULL;
    const vs_status_e search_status = _get_public_key_by_identity(vsc_str_from_str(recipient), &recipient_key_handler);
    CHECK_RET(search_status == VS_CODE_OK,
              search_status,
              "Failed to encrypt message (cannot get Recipient's public key)");

    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vsc_str_t plaintext = vsc_str_from_str(message);

    vsc_buffer_t *ciphertext = NULL;

    vssc_json_object_t *ciphertext_json = NULL;

    vscf_recipient_cipher_t *recipient_cipher = NULL;

    vs_status_e status = VS_CODE_ERR_CRYPTO;

    //
    //  Encrypt message.
    //
    vscf_random_padding_t *random_padding = vscf_random_padding_new();
    vscf_random_padding_use_random(random_padding, _config.rng);

    recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, _config.rng);
    vscf_recipient_cipher_take_encryption_padding(recipient_cipher, vscf_random_padding_impl(random_padding));
    random_padding = NULL;

    vscf_recipient_cipher_add_key_recipient(recipient_cipher,
                                            vssc_key_handler_key_id(recipient_key_handler),
                                            vssc_key_handler_key(recipient_key_handler));

    foundation_error.status = vscf_recipient_cipher_add_signer(
            recipient_cipher, vsc_buffer_data(_inner_creds.public_key_id), _inner_creds.private_key);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to encrypt message (cannot produce signature)");

    foundation_error.status = vscf_recipient_cipher_start_signed_encryption(recipient_cipher, plaintext.len);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to encrypt message (cipher failed)");

    const size_t ciphertext_len = vscf_recipient_cipher_message_info_len(recipient_cipher) +
                                  vscf_recipient_cipher_encryption_out_len(recipient_cipher, plaintext.len) +
                                  vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

    ciphertext = vsc_buffer_new_with_capacity(ciphertext_len);

    vscf_recipient_cipher_pack_message_info(recipient_cipher, ciphertext);

    foundation_error.status =
            vscf_recipient_cipher_process_encryption(recipient_cipher, vsc_str_as_data(plaintext), ciphertext);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to encrypt message (cipher failed)");

    foundation_error.status = vscf_recipient_cipher_finish_encryption(recipient_cipher, ciphertext);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to encrypt message (cipher failed)");


    const size_t footer_len = vscf_recipient_cipher_message_info_footer_len(recipient_cipher);
    vsc_buffer_reserve_unused(ciphertext, footer_len);

    foundation_error.status = vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, ciphertext);
    CHECK(!vscf_error_has_error(&foundation_error), "Failed to encrypt message (cipher failed)");

    vscf_recipient_cipher_destroy(&recipient_cipher);

    //
    //  Pack ciphertext to base64({"ciphertext":"BASE64=","version":"v2"}).
    //
    ciphertext_json = vssc_json_object_new();
    vssc_json_object_add_string_value(ciphertext_json, k_json_key_VERSION, k_json_value_V2);
    vssc_json_object_add_binary_value(ciphertext_json, k_json_key_CIPHERTEXT, vsc_buffer_data(ciphertext));
    vssc_json_object_add_int_value(ciphertext_json, k_json_key_DATE, (int)vssc_unix_time_now());

    vsc_str_t ciphertext_json_str = vssc_json_object_as_str(ciphertext_json);

    CHECK(buf_sz >= vscf_base64_encoded_len(ciphertext_json_str.len),
          "Failed to encrypt message (output buffer too small)");

    vsc_buffer_release(ciphertext);
    vsc_buffer_use(ciphertext, encrypted_message, buf_sz);

    vscf_base64_encode(vsc_str_as_data(ciphertext_json_str), ciphertext);

    *encrypted_message_sz = vsc_buffer_len(ciphertext);

    vsc_buffer_release(ciphertext);

    status = VS_CODE_OK;

terminate:

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&ciphertext);
    vssc_json_object_destroy(&ciphertext_json);
    vscf_recipient_cipher_destroy(&recipient_cipher);

    return status;
}

/******************************************************************************/
bool
vs_logger_output_hal(const char *buffer) {
    if (buffer) {
        fprintf(stdout, "%s", buffer);
        fflush(stdout);
    }

    return !!buffer;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_virgil_search(const char *identity) {
    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(vs_messenger_virgil_is_signed_in());

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(identity && identity[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    // Get Sender's public key.
    //
    const vssc_key_handler_t *key_handler = NULL;
    return _get_public_key_by_identity(vsc_str_from_str(identity), &key_handler);
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_keyknox_store_creds(const vs_messenger_virgil_user_creds_t *creds, const char *pwd, const char *alias) {

    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(vs_messenger_virgil_is_signed_in());

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(creds, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->pubkey_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->privkey_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->card_id[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(pwd && pwd[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(alias && alias[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    //  Update Virgil JWT first.
    //
    const vs_status_e update_jwt_status = _update_virgil_jwt_if_expired();
    CHECK_RET(update_jwt_status == VS_CODE_OK,
              update_jwt_status,
              "Failed to store credentials (cannot update Virgil JWT)");

    //
    //  Declare resources.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssp_error_t pythia_sdk_error;
    vssp_error_reset(&pythia_sdk_error);

    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vscf_status_t foundation_status = vscf_status_SUCCESS;

    vscf_impl_t *brain_private_key = NULL;
    vscf_impl_t *brain_public_key = NULL;
    vssc_json_object_t *credentials_json = NULL;
    vscf_recipient_cipher_t *cipher = NULL;

    vssc_http_request_t *http_request = NULL;
    vssc_virgil_http_response_t *http_response = NULL;

    vsc_buffer_t *keyknox_meta = NULL;
    vsc_buffer_t *keyknox_value = NULL;
    vssk_keyknox_client_t *keyknox_client = NULL;
    vssc_string_list_t *keyknox_identities = NULL;
    vssk_keyknox_entry_t *keyknox_entry = NULL;


    vs_status_e status = VS_CODE_ERR_MSGR_CRYPTO;

    //
    //  Generate Brain Key.
    //
    STATUS_CHECK(_generate_brain_key(pwd, _jwt, &brain_private_key, &brain_public_key), "Cannot generate brain key");

    //
    //  Pack Credentials.
    //  Format:
    //     {
    //         "version" : "1"
    //         "card_id" : "HEX_STRING",
    //         "private_key" : "BASE64_STRING",
    //         "public_key" : "BASE64_STRING",
    //         "public_key_id" : "BASE64_STRING"
    //     }
    credentials_json = vssc_json_object_new();
    vssc_json_object_add_int_value(credentials_json, k_brain_key_JSON_VERSION, 1);
    vssc_json_object_add_string_value(credentials_json, k_brain_key_JSON_CARD_ID, vsc_str_from_str(creds->card_id));
    vssc_json_object_add_binary_value(
            credentials_json, k_brain_key_JSON_PRIVATE_KEY, vsc_data(creds->privkey, creds->privkey_sz));
    vssc_json_object_add_binary_value(
            credentials_json, k_brain_key_JSON_PUBLIC_KEY, vsc_data(creds->pubkey, creds->pubkey_sz));
    vssc_json_object_add_binary_value(credentials_json,
                                      k_brain_key_JSON_PUBLIC_KEY_ID,
                                      vsc_data(creds->pubkey_id, VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ));

    //
    //  Encrypt Credentials.
    //
    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(cipher, k_brain_key_RECIPIENT_ID, brain_public_key);

    foundation_status = vscf_recipient_cipher_add_signer(cipher, k_brain_key_RECIPIENT_ID, brain_private_key);
    CHECK(foundation_status == vscf_status_SUCCESS, "Failed to encrypt credentials");

    foundation_status = vscf_recipient_cipher_start_encryption(cipher);
    CHECK(foundation_status == vscf_status_SUCCESS, "Failed to encrypt credentials");


    keyknox_meta = vsc_buffer_new_with_capacity(vscf_recipient_cipher_message_info_len(cipher));
    vscf_recipient_cipher_pack_message_info(cipher, keyknox_meta);

    keyknox_value = vsc_buffer_new_with_capacity(
            vscf_recipient_cipher_encryption_out_len(cipher, vssc_json_object_as_str(credentials_json).len) +
            vscf_recipient_cipher_encryption_out_len(cipher, 0));

    foundation_status = vscf_recipient_cipher_process_encryption(
            cipher, vsc_str_as_data(vssc_json_object_as_str(credentials_json)), keyknox_value);
    CHECK(foundation_status == vscf_status_SUCCESS, "Failed to encrypt credentials");

    vssc_json_object_destroy(&credentials_json);

    foundation_status = vscf_recipient_cipher_finish_encryption(cipher, keyknox_value);
    CHECK(foundation_status == vscf_status_SUCCESS, "Failed to encrypt credentials");

    vscf_recipient_cipher_destroy(&cipher);

    //
    //  Push encrypted credentials to the Keyknox.
    //

    status = VS_CODE_ERR_MSGR_SERVICE;

    keyknox_identities = vssc_string_list_new();
    vssc_string_list_add(keyknox_identities, vssc_jwt_identity(_jwt));

    keyknox_entry = vssk_keyknox_entry_new_with(k_keyknox_root_MESSENGER,
                                                k_keyknox_path_CREDENTIALS,
                                                vsc_str_from_str(alias),
                                                keyknox_identities,
                                                vsc_buffer_data(keyknox_meta),
                                                vsc_buffer_data(keyknox_value),
                                                vsc_data_empty());

    keyknox_client = vssk_keyknox_client_new();

    http_request = vssk_keyknox_client_make_request_push(keyknox_client, keyknox_entry);

    http_response = vssc_virgil_http_client_send_with_ca(http_request, _jwt, _ca_bundle(), &core_sdk_error);

    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to send encrypted credentials to the Keyknox");

    CHECK(vssc_virgil_http_response_is_success(http_response), "Failed to push encrypted credentials to the Keyknox");

    status = VS_CODE_OK;

terminate:

    vscf_impl_destroy(&brain_private_key);
    vscf_impl_destroy(&brain_public_key);
    vssc_json_object_destroy(&credentials_json);
    vscf_recipient_cipher_destroy(&cipher);
    vssc_http_request_destroy(&http_request);
    vssc_virgil_http_response_destroy(&http_response);
    vsc_buffer_destroy(&keyknox_meta);
    vsc_buffer_destroy(&keyknox_value);
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_string_list_destroy(&keyknox_identities);
    vssk_keyknox_entry_destroy(&keyknox_entry);

    return status;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_keyknox_load_creds(const char *pwd, const char *alias, vs_messenger_virgil_user_creds_t *creds) {

    //
    //  Check inner state.
    //
    VS_IOT_ASSERT(vs_messenger_virgil_is_init());

    //
    //  Check input parameters.
    //
    CHECK_NOT_ZERO_RET(pwd && pwd[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(alias && alias[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds, VS_CODE_ERR_INCORRECT_ARGUMENT);

    //
    //  Declare resources.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssp_error_t pythia_sdk_error;
    vssp_error_reset(&pythia_sdk_error);

    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vscf_status_t foundation_status = vscf_status_SUCCESS;
    vscf_recipient_cipher_t *cipher = NULL;
    vscf_impl_t *brain_private_key = NULL;
    vscf_impl_t *brain_public_key = NULL;

    vssc_jwt_t *jwt = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_virgil_http_response_t *http_response = NULL;

    vssk_keyknox_client_t *keyknox_client = NULL;
    vssk_keyknox_entry_t *keyknox_entry = NULL;

    vssc_json_object_t *credentials_json = NULL;

    const vscf_signer_info_list_t *signer_infos = NULL;
    const vscf_signer_info_t *signer_info = NULL;

    vsc_buffer_t *credentials_data = NULL;

    int credentials_version = -1;
    vsc_str_t credentials_card_id = vsc_str_empty();
    vsc_buffer_t *credentials_private_key = NULL;
    vsc_buffer_t *credentials_public_key = NULL;
    vsc_buffer_t *credentials_public_key_id = NULL;

    vs_status_e status = VS_CODE_ERR_MSGR_INTERNAL;

    //
    //  FIXME: request JWT based on the user login and password.
    //

    //
    //  Generate Brain Key.
    //
    STATUS_CHECK(_generate_brain_key(pwd, _jwt, &brain_private_key, &brain_public_key), "Cannot generate brain key");

    //
    //  Pull encrypted credentials from the Keyknox.
    //
    keyknox_client = vssk_keyknox_client_new();

    http_request = vssk_keyknox_client_make_request_pull(keyknox_client,
                                                         k_keyknox_root_MESSENGER,
                                                         k_keyknox_path_CREDENTIALS,
                                                         vsc_str_from_str(alias),
                                                         vssc_jwt_identity(jwt));

    http_response = vssc_virgil_http_client_send_with_ca(http_request, _jwt, _ca_bundle(), &core_sdk_error);

    CHECK(!vssc_error_has_error(&core_sdk_error),
          "Failed to get encrypted credentials from the Keyknox (cannot send request)");

    CHECK(vssc_virgil_http_response_is_success(http_response),
          "Failed to get encrypted credentials from the Keyknox (errored response)");


    keyknox_entry = vssk_keyknox_client_process_response_pull(http_response, &keyknox_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to get encrypted credentials from the Keyknox");


    //
    //  Decrypt Credentials.
    //
    cipher = vscf_recipient_cipher_new();

    foundation_status = vscf_recipient_cipher_start_decryption_with_key(
            cipher, k_brain_key_RECIPIENT_ID, brain_private_key, vssk_keyknox_entry_meta(keyknox_entry));
    CHECK(foundation_status == vscf_status_SUCCESS, "Failed to decrypt credentials");


    credentials_data = vsc_buffer_new_with_capacity(
            vscf_recipient_cipher_decryption_out_len(cipher, vssk_keyknox_entry_value(keyknox_entry).len) +
            vscf_recipient_cipher_decryption_out_len(cipher, 0));

    foundation_status =
            vscf_recipient_cipher_process_decryption(cipher, vssk_keyknox_entry_value(keyknox_entry), credentials_data);
    CHECK(foundation_status == vscf_status_SUCCESS, "Failed to decrypt credentials");

    foundation_status = vscf_recipient_cipher_finish_decryption(cipher, credentials_data);
    CHECK(foundation_status == vscf_status_SUCCESS, "Failed to decrypt credentials");

    //
    //  Verify Credentials.
    //
    CHECK(vscf_recipient_cipher_is_data_signed(cipher), "Failed to verify credentials");

    signer_infos = vscf_recipient_cipher_signer_infos(cipher);

    CHECK(vscf_signer_info_list_has_item(signer_infos), "Failed to verify credentials");

    signer_info = vscf_signer_info_list_item(signer_infos);

    CHECK(vsc_data_equal(k_brain_key_RECIPIENT_ID, vscf_signer_info_signer_id(signer_info)),
          "Failed to verify credentials");

    CHECK(vscf_recipient_cipher_verify_signer_info(cipher, signer_info, brain_public_key),
          "Failed to verify credentials");

    vscf_recipient_cipher_destroy(&cipher);

    //
    //  Unpack Credentials.
    //  Format:
    //     {
    //         "version" : "1"
    //         "card_id" : "HEX_STRING",
    //         "private_key" : "BASE64_STRING",
    //         "public_key" : "BASE64_STRING",
    //         "public_key_id" : "BASE64_STRING"
    //     }
    credentials_json = vssc_json_object_parse(vsc_str_from_data(vsc_buffer_data(credentials_data)), &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (invalid json)");

    credentials_version = vssc_json_object_get_int_value(credentials_json, k_brain_key_JSON_VERSION, &core_sdk_error);

    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no version)");
    CHECK(1 == credentials_version, "Failed to parse credentials (version mismatch)");

    credentials_card_id =
            vssc_json_object_get_string_value(credentials_json, k_brain_key_JSON_CARD_ID, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no card_id)");
    CHECK(credentials_card_id.len > 0, "Failed to parse credentials (empty card_id)");
    CHECK(credentials_card_id.len < VS_MESSENGER_VIRGIL_CARD_ID_SZ_MAX,
          "Failed to parse credentials (card_id too big)");

    credentials_private_key =
            vssc_json_object_get_binary_value_new(credentials_json, k_brain_key_JSON_PRIVATE_KEY, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no private_key)");

    CHECK(vsc_buffer_len(credentials_private_key) <= VS_MESSENGER_VIRGIL_KEY_SZ_MAX,
          "Failed to parse credentials (private key too big)");

    credentials_public_key =
            vssc_json_object_get_binary_value_new(credentials_json, k_brain_key_JSON_PUBLIC_KEY, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no public_key)");

    CHECK(vsc_buffer_len(credentials_public_key) <= VS_MESSENGER_VIRGIL_KEY_SZ_MAX,
          "Failed to parse credentials (public key too big)");

    credentials_public_key_id =
            vssc_json_object_get_binary_value_new(credentials_json, k_brain_key_JSON_PUBLIC_KEY_ID, &core_sdk_error);
    CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no public_key_id)");

    CHECK(VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ == vsc_buffer_len(credentials_public_key_id),
          "Failed to parse credentials (public_key_id length mismatch)");

    //
    //  Fulfil Credentials.
    //
    VS_IOT_MEMCPY(
            creds->pubkey_id, vsc_buffer_bytes(credentials_public_key_id), vsc_buffer_len(credentials_public_key_id));

    creds->pubkey_sz = vsc_buffer_len(credentials_public_key);
    VS_IOT_MEMCPY(creds->pubkey, vsc_buffer_bytes(credentials_public_key), vsc_buffer_len(credentials_public_key));

    creds->privkey_sz = vsc_buffer_len(credentials_private_key);
    VS_IOT_MEMCPY(creds->privkey, vsc_buffer_bytes(credentials_private_key), vsc_buffer_len(credentials_private_key));

    VS_IOT_MEMCPY(creds->card_id, credentials_card_id.chars, credentials_card_id.len);
    creds->card_id[credentials_card_id.len] = '\0';

    status = VS_CODE_OK;

terminate:

    vscf_recipient_cipher_destroy(&cipher);
    vscf_impl_destroy(&brain_private_key);
    vscf_impl_destroy(&brain_public_key);
    vssc_jwt_destroy(&jwt);
    vssc_http_request_destroy(&http_request);
    vssc_virgil_http_response_destroy(&http_response);
    vssk_keyknox_client_destroy(&keyknox_client);
    vssk_keyknox_entry_destroy(&keyknox_entry);
    vssc_json_object_destroy(&credentials_json);
    vsc_buffer_destroy(&credentials_data);
    vsc_buffer_destroy(&credentials_private_key);
    vsc_buffer_destroy(&credentials_public_key);
    vsc_buffer_destroy(&credentials_public_key_id);

    return status;
}

/******************************************************************************/
