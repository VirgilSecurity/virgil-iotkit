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
using namespace VirgilIoTKit;

#include "private/visibility.h"

#include <virgil/iot/messenger/crypto/msgr-crypto.h>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/CardClient.h>
#include <virgil/sdk/client/models/RawCardContent.h>
#include <virgil/sdk/client/networking/Request.h>
#include <virgil/sdk/client/networking/Response.h>
#include <virgil/sdk/client/networking/Connection.h>
#include <virgil/sdk/cards/ModelSigner.h>
#include <virgil/sdk/cards/CardManager.h>
#include <virgil/sdk/serialization/JsonSerializer.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/crypto/common/vsc_str_mutable.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_key_material_rng.h>
#include <virgil/crypto/foundation/vscf_recipient_cipher.h>
#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_public_key.h>
#include <virgil/crypto/pythia/vscp_pythia.h>

#include <virgil/sdk/core/vssc_virgil_http_client.h>
#include <virgil/sdk/core/private/vssc_json_object_private.h>
#include <virgil/sdk/pythia/vssp_pythia_client.h>
#include <virgil/sdk/keyknox/vssk_keyknox_client.h>

#include <string.h>


using nlohmann::json;
using virgil::sdk::VirgilBase64;
using virgil::sdk::VirgilHashAlgorithm;
using virgil::sdk::cards::Card;
using virgil::sdk::cards::CardManager;
using virgil::sdk::cards::ModelSigner;
using virgil::sdk::client::CardClient;
using virgil::sdk::client::models::RawCardContent;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::client::networking::Connection;
using virgil::sdk::client::networking::Request;
using virgil::sdk::client::networking::Response;
using virgil::sdk::client::networking::errors::Error;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::serialization::JsonDeserializer;
using virgil::sdk::serialization::JsonSerializer;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;

using virgil::crypto::bytes2hex;
using virgil::crypto::hex2bytes;
using virgil::crypto::str2bytes;

#include <iostream>

// Limits
#define VS_VIRGIL_MESSENGER_ENC_DATA_MAX_SZ (4 * 1024) /**< Maximum size of encrypted data */

/** Container of information about Public key */
typedef struct {
    VirgilByteArray pubkey;
    VirgilByteArray pubkeyId;
} vs_pubkey_info_t;


/** Cache for Public keys */
typedef std::map<std::string, vs_pubkey_info_t> vs_pubkey_cache_t;

// Endpoints
static const char *_virgil_jwt_endpoint = "/virgil-jwt/";
static const char *_ejabberd_jwt_endpoint = "/ejabberd-jwt/";
static const char *_sign_up_endpoint = "/signup/";

// Brain Key configuration
#define MAKE_STR_CONSTANT(name, value)                                                                                 \
    static const char name##_CHARS[] = value;                                                                          \
    static const vsc_str_t name = {name##_CHARS, sizeof(name##_CHARS) - 1};

#define MAKE_DATA_CONSTANT_FROM_STR(name, value)                                                                       \
    static const byte name##_BYTES[] = value;                                                                          \
    static const vsc_data_t name = {name##_BYTES, sizeof(name##_BYTES) - 1};


MAKE_DATA_CONSTANT_FROM_STR(k_brain_key_RECIPIENT_ID, "brain_key")

MAKE_STR_CONSTANT(k_brain_key_JSON_VERSION, "version")
MAKE_STR_CONSTANT(k_brain_key_JSON_CARD_ID, "card_id")
MAKE_STR_CONSTANT(k_brain_key_JSON_PRIVATE_KEY, "private_key")
MAKE_STR_CONSTANT(k_brain_key_JSON_PUBLIC_KEY, "public_key")
MAKE_STR_CONSTANT(k_brain_key_JSON_PUBLIC_KEY_ID, "public_key_id")

MAKE_STR_CONSTANT(k_keyknox_root_MESSENGER, "messenger")
MAKE_STR_CONSTANT(k_keyknox_path_CREDENTIALS, "credentials")

// Module variables
static bool _is_initialized = false;
static bool _is_credentials_ready = false;
static std::shared_ptr<Crypto> crypto;
static vs_messenger_virgil_user_creds_t _creds = {{0}, 0, {0}, 0, {0}};
static char *_service_base_url = NULL;
static vsc_str_mutable_t _custom_ca = {NULL, 0};
static vs_pubkey_cache_t _pubkey_cache;
static char virgil_token[VS_MESSENGER_VIRGIL_TOKEN_SZ_MAX] = {0};
static bool _is_virgil_token_ready = false;

/******************************************************************************/
static vs_status_e
_get_token(const char *endpoint, char *token, size_t token_buf_sz) {

    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    // Check input parameters
    CHECK_NOT_ZERO(endpoint && endpoint[0]);
    CHECK_NOT_ZERO(token);
    CHECK_NOT_ZERO(token_buf_sz);

    try {
        // Create Auth header
        auto signStr = std::string(_creds.card_id) + "." + std::to_string(static_cast<unsigned long>(time(NULL)));
        auto privateKey =
                crypto->importPrivateKey(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(_creds.privkey, _creds.privkey_sz));
        auto sign = crypto->generateSignature(str2bytes(signStr), privateKey);
        auto authHeader = std::string("Bearer ") + signStr + "." + VirgilBase64::encode(sign);

        // Prepare request
        Request::Header header;
        header["Authorization"] = authHeader;

        auto httpRequest = Request();
        httpRequest.baseAddress(_service_base_url).endpoint(endpoint).header(header).get();

        // Request to service
        Connection connection;
        Response response = connection.send(httpRequest);
        CHECK(!response.fail(), "Response: %d Body: %s", response.statusCodeRaw(), response.body().c_str());

        // Parse response
        auto responseJSON = json::parse(response.body());
        std::string tokenStd = responseJSON["token"];
        CHECK(tokenStd.length() < token_buf_sz, "Token buffer too small");
        strcpy(token, tokenStd.c_str());

        // Print results
        VS_LOG_INFO("%s : %s", endpoint, token);

    } catch (const std::exception &exception) {
        CHECK(false, "%s", exception.what());
    } catch (...) {
        CHECK(false, "Get token error");
    }

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
static const char *
_prepare_virgil_token(void) {

    // TODO: Update Virgil token by time. Every 2 hours.

    if (!_is_virgil_token_ready) {
        if (VS_CODE_OK == _get_token(_virgil_jwt_endpoint, virgil_token, VS_MESSENGER_VIRGIL_TOKEN_SZ_MAX)) {
            _is_virgil_token_ready = true;
        }
    }

    if (!_is_virgil_token_ready) {
        VS_LOG_ERROR("Cannot get Virgil token");
    }

    return _is_virgil_token_ready ? virgil_token : NULL;
}

/******************************************************************************/
static VirgilByteArray
_computeHashForPublicKey(const VirgilByteArray &publicKey) {
    VirgilByteArray hash = crypto->computeHash(VirgilKeyPair::publicKeyToDER(publicKey), VirgilHashAlgorithm::SHA512);
    hash.resize(VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ);

    return hash;
}

/******************************************************************************/
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_virgil_init(const char *service_base_url, const char *custom_ca) {
    setlocale(LC_NUMERIC, "C");
    if (_is_initialized) {
        VS_LOG_WARNING("Virgil Messenger is initialized");
        return VS_CODE_ERR_MSGR_INTERNAL;
    }

    vs_logger_init(VS_LOGLEV_DEBUG);

    // Save custom CA
    if (custom_ca && custom_ca[0]) {
        VS_LOG_INFO("Set custom CA: %s", custom_ca);
        Connection::setCA(std::string(custom_ca));
        _custom_ca = vsc_str_mutable_from_str(vsc_str_from_str(custom_ca));
    } else {
        Connection::setCA("");
        _custom_ca = vsc_str_mutable_from_str(vsc_str_empty());
    }

    // Check input parameters
    CHECK_NOT_ZERO_RET(service_base_url && service_base_url[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    crypto = std::make_shared<Crypto>();
    _service_base_url = strdup(service_base_url);

    // configure pythia
    const vscp_status_t pythia_status = vscp_pythia_configure();
    if (pythia_status != vscp_status_SUCCESS) {
        VS_LOG_ERROR("Cannot initialize Pythia crypto library");
        return VS_CODE_ERR_MSGR_INTERNAL;
    }

    _is_initialized = true;

    return VS_CODE_OK;
}

/******************************************************************************/
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_virgil_sign_in(const vs_messenger_virgil_user_creds_t *creds) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    VS_IOT_ASSERT(_is_initialized);

    // Check input parameters
    CHECK_NOT_ZERO(creds);
    CHECK_NOT_ZERO(creds->pubkey_sz);
    CHECK_NOT_ZERO(creds->privkey_sz);
    CHECK_NOT_ZERO(creds->card_id[0]);

    // Save parameters
    VS_IOT_MEMCPY(&_creds, creds, sizeof(*creds));

    // Get Virgil token
    res = _prepare_virgil_token() ? VS_CODE_OK : VS_CODE_ERR_MSGR_INTERNAL;

    _is_credentials_ready = VS_CODE_OK == res;

terminate:

    return res;
}

/******************************************************************************/
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_virgil_sign_up(const char *identity, vs_messenger_virgil_user_creds_t *creds) {

    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

    VS_IOT_ASSERT(_is_initialized);

    // Check input parameters
    CHECK_NOT_ZERO(identity && identity[0]);
    CHECK_NOT_ZERO(creds);

    // Clean destination data
    VS_IOT_MEMSET(creds, 0, sizeof(*creds));

    try {
        // Generate Key-pair
        ModelSigner modelSigner(crypto);
        auto keyPair = crypto->generateKeyPair();
        auto publicKeyData = crypto->exportPublicKey(keyPair.publicKey());
        auto privateKeyData = crypto->exportPrivateKey(keyPair.privateKey());

        // Create request for a card creation
        RawCardContent content(identity, publicKeyData, std::time(0));
        auto snapshot = content.snapshot();
        RawSignedModel rawCard(snapshot);
        modelSigner.selfSign(rawCard, keyPair.privateKey());
        auto exportedRawCard = rawCard.exportAsJson();

        // Registration request
        auto internalJSON = json::parse(JsonSerializer<RawSignedModel>::toJson(rawCard));
        json requestJSON = {{"raw_card", internalJSON}};
        auto httpRequest = Request();
        httpRequest.baseAddress(_service_base_url)
                .endpoint(_sign_up_endpoint)
                .contentType("application/json")
                .body(requestJSON.dump())
                .post();

        Connection connection;
        Response response = connection.send(httpRequest);

        // Check and parse response
        if (response.fail()) {
            VS_LOG_ERROR("%d : %s", response.statusCodeRaw(), response.body().c_str());
            return VS_CODE_ERR_MSGR_INTERNAL;
        }
        auto responseJSON = json::parse(response.body());
        auto cardJSON = responseJSON["virgil_card"].dump();
        auto readyCard = JsonDeserializer<RawSignedModel>::fromJsonString(cardJSON);
        auto parsedCard = CardManager::parseCard(rawCard, crypto);
        auto cardId = parsedCard.identifier();

        // Prepare result

        //      Public key ID
        auto pubkeyId = _computeHashForPublicKey(publicKeyData);
        CHECK(VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ == pubkeyId.size(), "Wrong size of public key ID");
        VS_IOT_MEMCPY(creds->pubkey_id, pubkeyId.data(), pubkeyId.size());

        //      Public key data
        CHECK(publicKeyData.size() <= sizeof(creds->pubkey), "Wrong size of public key");
        creds->pubkey_sz = publicKeyData.size();
        VS_IOT_MEMCPY(creds->pubkey, publicKeyData.data(), creds->pubkey_sz);

        //      Private key data
        CHECK(privateKeyData.size() <= sizeof(creds->privkey), "Wrong size of private key");
        creds->privkey_sz = privateKeyData.size();
        VS_IOT_MEMCPY(creds->privkey, privateKeyData.data(), creds->privkey_sz);

        //      Card ID
        CHECK(cardId.size() < sizeof(creds->card_id), "Wrong size of Card ID");
        VS_IOT_MEMCPY(creds->card_id, cardId.c_str(), cardId.size() + 1);

        // Print results
        VS_LOG_DEBUG("Public key    : %s", bytes2hex(publicKeyData).c_str());
        VS_LOG_DEBUG("Private key   : %s", bytes2hex(privateKeyData).c_str());
        VS_LOG_DEBUG("Card ID       : %s", cardId.c_str());
        VS_LOG_DEBUG("Public key ID : %s", bytes2hex(pubkeyId).c_str());

        // Make a local copy of credentials
        VS_IOT_MEMCPY(&_creds, creds, sizeof(*creds));
    } catch (const std::exception &exception) {
        CHECK(false, "%s", exception.what());
    } catch (...) {
        CHECK(false, "Sign Up error");
    }

    // Get Virgil token
    res = _prepare_virgil_token() ? VS_CODE_OK : VS_CODE_ERR_MSGR_INTERNAL;

    _is_credentials_ready = VS_CODE_OK == res;

terminate:

    return res;
}

/******************************************************************************/
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_virgil_get_xmpp_pass(char *pass, size_t pass_buf_sz) {
    VS_IOT_ASSERT(_is_initialized);

    // Check input parameters
    CHECK_NOT_ZERO_RET(pass, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(pass_buf_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(_is_credentials_ready, VS_CODE_ERR_MSGR_INTERNAL, "Virgil Messenger is not ready for a communication");
    return _get_token(_ejabberd_jwt_endpoint, pass, pass_buf_sz);
}

/******************************************************************************/
extern "C" DLL_PUBLIC void
vs_messenger_virgil_logout(void) {
    crypto = nullptr;

    vsc_str_mutable_release(&_custom_ca);
    vscp_pythia_cleanup();

    free(_service_base_url);
    _service_base_url = NULL;

    _is_credentials_ready = false;
    _is_initialized = false;
    _is_virgil_token_ready = false;
}

/******************************************************************************/
static vs_status_e
_pubkey_by_identity(const char *identity, vs_pubkey_info_t &pubkeyInfo) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;
    auto found_it = _pubkey_cache.find(identity);

    // Check input parameters
    CHECK_NOT_ZERO(identity && identity[0]);

    // Try to find by identity in cache
    if (found_it != _pubkey_cache.end()) {
        pubkeyInfo = _pubkey_cache[identity];
        return VS_CODE_OK;
    }

    // There is no cached public key, let's get it from the Cloud
    try {
        // Get Sender's public key
        CardClient cardClient;
        auto virgil_token = _prepare_virgil_token();
        CHECK_NOT_ZERO_RET(virgil_token, VS_CODE_ERR_MSGR_INTERNAL);

        auto searchFuture = cardClient.searchCards(identity, virgil_token);
        auto rawCards = searchFuture.get();
        CHECK_NOT_ZERO(rawCards.size());
        auto parsedCard = CardManager::parseCard(rawCards.front(), crypto);
        auto sdkPubkey = parsedCard.publicKey();
        pubkeyInfo.pubkey = crypto->exportPublicKey(sdkPubkey);
        pubkeyInfo.pubkeyId = _computeHashForPublicKey(pubkeyInfo.pubkey);

        // Save data to cache
        _pubkey_cache[identity] = pubkeyInfo;

    } catch (const std::exception &exception) {
        CHECK(false, "%s", exception.what());
    } catch (...) {
        CHECK(false, "Card by identity error");
    }

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_virgil_decrypt_msg(const char *sender,
                                const char *encrypted_message,
                                uint8_t *decrypted_message,
                                size_t buf_sz,
                                size_t *decrypted_message_sz) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;
    vs_pubkey_info_t senderPubkeyInfo;

    // Check input parameters
    CHECK_NOT_ZERO(sender && sender[0]);
    CHECK_NOT_ZERO(decrypted_message);
    CHECK_NOT_ZERO(buf_sz);
    CHECK_NOT_ZERO(decrypted_message_sz);

    // Check is correctly initialized
    VS_IOT_ASSERT(_is_initialized);
    CHECK_RET(_is_credentials_ready, VS_CODE_ERR_MSGR_INTERNAL, "Virgil Messenger is not ready for a communication");

    // Get Sender's public key
    STATUS_CHECK(_pubkey_by_identity(sender, senderPubkeyInfo), "Cannot get Sender's public key");

    try {

        // Get cipher text
        auto encMessageTxt = VirgilByteArrayUtils::bytesToString(VirgilBase64::decode(encrypted_message));
        auto encMessageJSON = json::parse(encMessageTxt);
        std::string ciphertextBase64 = encMessageJSON["ciphertext"];
        auto encData = VirgilBase64::decode(ciphertextBase64);

        // Decrypt message
        STATUS_CHECK(vs_messenger_crypto_decrypt(encData.data(),
                                                 encData.size(),
                                                 _creds.privkey,
                                                 _creds.privkey_sz,
                                                 _creds.pubkey_id,
                                                 VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ,
                                                 senderPubkeyInfo.pubkey.data(),
                                                 senderPubkeyInfo.pubkey.size(),
                                                 senderPubkeyInfo.pubkeyId.data(),
                                                 senderPubkeyInfo.pubkeyId.size(),
                                                 decrypted_message,
                                                 buf_sz,
                                                 decrypted_message_sz),
                     "Cannon decrypt message");

    } catch (const std::exception &exception) {
        CHECK(false, "%s", exception.what());
    } catch (...) {
        CHECK(false, "Decryption error");
    }

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_virgil_encrypt_msg(const char *recipient,
                                const char *message,
                                uint8_t *encrypted_message,
                                size_t buf_sz,
                                size_t *encrypted_message_sz) {

    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;
    uint8_t enc_data[VS_VIRGIL_MESSENGER_ENC_DATA_MAX_SZ];
    size_t enc_data_sz = 0;

    // Check is correctly initialized
    CHECK_RET(_is_initialized, VS_CODE_ERR_MSGR_INTERNAL, "Virgil Messenger is not ready for a communication");
    CHECK_RET(_is_credentials_ready, VS_CODE_ERR_MSGR_INTERNAL, "Virgil Messenger is not ready for a communication");

    // Get Recipient's public key
    vs_pubkey_info_t recipientPubkey;
    STATUS_CHECK(_pubkey_by_identity(recipient, recipientPubkey), "Cannot get Recipient's public key");

    try {

        // Encrypt message
        STATUS_CHECK(vs_messenger_crypto_encrypt((const uint8_t *)message,
                                                 strlen(message),
                                                 recipientPubkey.pubkey.data(),
                                                 recipientPubkey.pubkey.size(),
                                                 recipientPubkey.pubkeyId.data(),
                                                 recipientPubkey.pubkeyId.size(),
                                                 _creds.privkey,
                                                 _creds.privkey_sz,
                                                 _creds.pubkey_id,
                                                 VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ,
                                                 enc_data,
                                                 sizeof(enc_data),
                                                 &enc_data_sz),
                     "Cannot encrypt message");

        // Base64 of encrypted data
        auto encData = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(enc_data, enc_data_sz);
        auto encDataBase64 = VirgilBase64::encode(encData);

        // Create JSON with ciphertext
        auto now = static_cast<double>(time(NULL));
        json encJSON = {{"ciphertext", encDataBase64}, {"version", "v2"}, {"date", now}};

        // Base64 of JSON structure
        std::string encJsonBase64 = VirgilBase64::encode(str2bytes(encJSON.dump()));

        // Set encrypted data as result
        CHECK(encJsonBase64.size() < buf_sz, "Cannot save encrypted data. Buffer too small.");
        VS_IOT_MEMSET(encrypted_message, 0, buf_sz);
        *encrypted_message_sz = encJsonBase64.size() + 1;
        VS_IOT_MEMCPY(encrypted_message, encJsonBase64.c_str(), *encrypted_message_sz);

    } catch (const std::exception &exception) {
        CHECK(false, "%s", exception.what());
    } catch (...) {
        CHECK(false, "Encryption error");
    }

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
extern "C" bool
vs_logger_output_hal(const char *buffer) {
    if (buffer) {
        std::cout << buffer << std::flush;
    }

    return !!buffer;
}

/******************************************************************************/
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_virgil_search(const char *identity) {
    vs_pubkey_info_t senderPubkeyInfo;

    // Check input parameters
    CHECK_NOT_ZERO_RET(identity && identity[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Check is correctly initialized
    VS_IOT_ASSERT(_is_initialized);
    CHECK_RET(_is_credentials_ready, VS_CODE_ERR_MSGR_INTERNAL, "Virgil Messenger is not ready for a communication");

    // Get Sender's public key
    return _pubkey_by_identity(identity, senderPubkeyInfo);
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
    BOOL_CHECK(pythia_status == vscp_status_SUCCESS, "Failed to blind password");

    //
    //  Get seed.
    //
    pythia_client = vssp_pythia_client_new_with_base_url(vsc_str_from_str(_service_base_url));

    http_request = vssp_pythia_client_make_request_generate_seed(pythia_client, vsc_buffer_data(blinded_password));

    vsc_buffer_destroy(&blinded_password);

    http_response = vssc_virgil_http_client_send(http_request, jwt, &core_sdk_error);
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to generate brain key seed");

    seed = vssp_pythia_client_process_response_generate_seed(pythia_client, http_response, &pythia_sdk_error);
    BOOL_CHECK(!vssp_error_has_error(&pythia_sdk_error), "Failed to generate brain key seed");

    vssc_http_request_destroy(&http_request);
    vssc_virgil_http_response_destroy(&http_response);

    deblinded_password = vsc_buffer_new_with_capacity(vscp_pythia_deblinded_password_buf_len());

    pythia_status =
            vscp_pythia_deblind(vssp_brain_key_seed_get(seed), vsc_buffer_data(blinding_secret), deblinded_password);

    BOOL_CHECK(pythia_status == vscp_status_SUCCESS, "Failed to deblind password");

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
    BOOL_CHECK(*private_key != NULL, "Failed to generate brain key");

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

extern "C" DLL_PUBLIC vs_status_e
vs_messenger_keyknox_store_creds(const vs_messenger_virgil_user_creds_t *creds, const char *pwd, const char *alias) {

    // Check is correctly initialized
    CHECK_RET(_is_initialized, VS_CODE_ERR_MSGR_INTERNAL, "Virgil Messenger is not initialized");
    CHECK_RET(_is_credentials_ready, VS_CODE_ERR_MSGR_INTERNAL, "Virgil Messenger is not signed in");

    // Check input parameters
    CHECK_NOT_ZERO_RET(creds, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->pubkey_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->privkey_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds->card_id[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(pwd && pwd[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(alias && alias[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

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

    vssc_jwt_t *jwt = NULL;
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

    //
    //  Import JWT.
    //
    jwt = vssc_jwt_parse(vsc_str_from_str(virgil_token), &core_sdk_error);
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse JWT");

    //
    //  Generate Brain Key.
    //
    STATUS_CHECK(_generate_brain_key(pwd, jwt, &brain_private_key, &brain_public_key), "Cannot generate brain key");

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
    vssc_json_object_add_string_value(credentials_json, k_brain_key_JSON_CARD_ID, vsc_str_from_str(_creds.card_id));
    vssc_json_object_add_binary_value(
            credentials_json, k_brain_key_JSON_PRIVATE_KEY, vsc_data(_creds.privkey, _creds.privkey_sz));
    vssc_json_object_add_binary_value(
            credentials_json, k_brain_key_JSON_PUBLIC_KEY, vsc_data(_creds.pubkey, _creds.pubkey_sz));
    vssc_json_object_add_binary_value(credentials_json,
                                      k_brain_key_JSON_PUBLIC_KEY_ID,
                                      vsc_data(_creds.pubkey_id, VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ));

    //
    //  Encrypt Credentials.
    //
    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(cipher, k_brain_key_RECIPIENT_ID, brain_public_key);

    foundation_status = vscf_recipient_cipher_add_signer(cipher, k_brain_key_RECIPIENT_ID, brain_private_key);
    BOOL_CHECK(foundation_status == vscf_status_SUCCESS, "Failed to encrypt credentials");

    foundation_status = vscf_recipient_cipher_start_encryption(cipher);
    BOOL_CHECK(foundation_status == vscf_status_SUCCESS, "Failed to encrypt credentials");


    keyknox_meta = vsc_buffer_new_with_capacity(vscf_recipient_cipher_message_info_len(cipher));
    vscf_recipient_cipher_pack_message_info(cipher, keyknox_meta);

    keyknox_value = vsc_buffer_new_with_capacity(
            vscf_recipient_cipher_encryption_out_len(cipher, vssc_json_object_as_str(credentials_json).len) +
            vscf_recipient_cipher_encryption_out_len(cipher, 0));

    foundation_status = vscf_recipient_cipher_process_encryption(
            cipher, vsc_str_as_data(vssc_json_object_as_str(credentials_json)), keyknox_value);
    BOOL_CHECK(foundation_status == vscf_status_SUCCESS, "Failed to encrypt credentials");

    vssc_json_object_destroy(&credentials_json);

    foundation_status = vscf_recipient_cipher_finish_encryption(cipher, keyknox_value);
    BOOL_CHECK(foundation_status == vscf_status_SUCCESS, "Failed to encrypt credentials");

    vscf_recipient_cipher_destroy(&cipher);

    //
    //  Push encrypted credentials to the Keyknox.
    //
    keyknox_identities = vssc_string_list_new();
    vssc_string_list_add(keyknox_identities, vssc_jwt_identity(jwt));

    keyknox_entry = vssk_keyknox_entry_new_with(k_keyknox_root_MESSENGER,
                                                k_keyknox_path_CREDENTIALS,
                                                vsc_str_from_str(alias),
                                                keyknox_identities,
                                                vsc_buffer_data(keyknox_meta),
                                                vsc_buffer_data(keyknox_value),
                                                vsc_data_empty());

    keyknox_client = vssk_keyknox_client_new_with_base_url(vsc_str_from_str(_service_base_url));

    http_request = vssk_keyknox_client_make_request_push(keyknox_client, keyknox_entry);

    http_response = vssc_virgil_http_client_send_with_custom_ca(
            http_request, jwt, vsc_str_mutable_as_str(_custom_ca), &core_sdk_error);

    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to send encrypted credentials to the Keyknox");

    BOOL_CHECK(vssc_virgil_http_response_is_success(http_response),
               "Failed to push encrypted credentials to the Keyknox");

    res = VS_CODE_OK;

terminate:

    vssc_jwt_destroy(&jwt);
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

    return res;
}

/******************************************************************************/
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_keyknox_load_creds(const char *pwd, const char *alias, vs_messenger_virgil_user_creds_t *creds) {

    // Check is correctly initialized
    CHECK_RET(_is_initialized, VS_CODE_ERR_MSGR_INTERNAL, "Virgil Messenger is not initialized");

    // Check input parameters
    CHECK_NOT_ZERO_RET(pwd && pwd[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(alias && alias[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(creds, VS_CODE_ERR_INCORRECT_ARGUMENT);

    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;

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

    //
    //  Import JWT.
    //
    jwt = vssc_jwt_parse(vsc_str_from_str(virgil_token), &core_sdk_error);
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse JWT");

    //
    //  Generate Brain Key.
    //
    STATUS_CHECK(_generate_brain_key(pwd, jwt, &brain_private_key, &brain_public_key), "Cannot generate brain key");

    //
    //  Pull encrypted credentials from the Keyknox.
    //
    keyknox_client = vssk_keyknox_client_new_with_base_url(vsc_str_from_str(_service_base_url));

    http_request = vssk_keyknox_client_make_request_pull(keyknox_client,
                                                         k_keyknox_root_MESSENGER,
                                                         k_keyknox_path_CREDENTIALS,
                                                         vsc_str_from_str(alias),
                                                         vssc_jwt_identity(jwt));

    http_response = vssc_virgil_http_client_send_with_custom_ca(
            http_request, jwt, vsc_str_mutable_as_str(_custom_ca), &core_sdk_error);

    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to get encrypted credentials from the Keyknox");

    BOOL_CHECK(vssc_virgil_http_response_is_success(http_response),
               "Failed to get encrypted credentials from the Keyknox");


    keyknox_entry = vssk_keyknox_client_process_response_pull(keyknox_client, http_response, &keyknox_error);
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to get encrypted credentials from the Keyknox");


    //
    //  Decrypt Credentials.
    //
    cipher = vscf_recipient_cipher_new();

    foundation_status = vscf_recipient_cipher_start_decryption_with_key(
            cipher, k_brain_key_RECIPIENT_ID, brain_private_key, vssk_keyknox_entry_meta(keyknox_entry));
    BOOL_CHECK(foundation_status == vscf_status_SUCCESS, "Failed to decrypt credentials");


    credentials_data = vsc_buffer_new_with_capacity(
            vscf_recipient_cipher_decryption_out_len(cipher, vssk_keyknox_entry_value(keyknox_entry).len) +
            vscf_recipient_cipher_decryption_out_len(cipher, 0));

    foundation_status =
            vscf_recipient_cipher_process_decryption(cipher, vssk_keyknox_entry_value(keyknox_entry), credentials_data);
    BOOL_CHECK(foundation_status == vscf_status_SUCCESS, "Failed to decrypt credentials");

    foundation_status = vscf_recipient_cipher_finish_decryption(cipher, credentials_data);
    BOOL_CHECK(foundation_status == vscf_status_SUCCESS, "Failed to decrypt credentials");

    //
    //  Verify Credentials.
    //
    BOOL_CHECK(vscf_recipient_cipher_is_data_signed(cipher), "Failed to verify credentials");

    signer_infos = vscf_recipient_cipher_signer_infos(cipher);

    BOOL_CHECK(vscf_signer_info_list_has_item(signer_infos), "Failed to verify credentials");

    signer_info = vscf_signer_info_list_item(signer_infos);

    BOOL_CHECK(vsc_data_equal(k_brain_key_RECIPIENT_ID, vscf_signer_info_signer_id(signer_info)),
               "Failed to verify credentials");

    BOOL_CHECK(vscf_recipient_cipher_verify_signer_info(cipher, signer_info, brain_public_key),
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
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (invalid json)");

    credentials_version = vssc_json_object_get_int_value(credentials_json, k_brain_key_JSON_VERSION, &core_sdk_error);

    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no version)");
    BOOL_CHECK(1 == credentials_version, "Failed to parse credentials (version mismatch)");

    credentials_card_id =
            vssc_json_object_get_string_value(credentials_json, k_brain_key_JSON_CARD_ID, &core_sdk_error);
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no card_id)");
    BOOL_CHECK(credentials_card_id.len > 0, "Failed to parse credentials (empty card_id)");
    BOOL_CHECK(credentials_card_id.len < VS_MESSENGER_VIRGIL_CARD_ID_SZ_MAX,
               "Failed to parse credentials (card_id too big)");

    credentials_private_key =
            vssc_json_object_get_binary_value_new(credentials_json, k_brain_key_JSON_PRIVATE_KEY, &core_sdk_error);
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no private_key)");

    BOOL_CHECK(vsc_buffer_len(credentials_private_key) <= VS_MESSENGER_VIRGIL_KEY_SZ_MAX,
               "Failed to parse credentials (private key too big)");

    credentials_public_key =
            vssc_json_object_get_binary_value_new(credentials_json, k_brain_key_JSON_PUBLIC_KEY, &core_sdk_error);
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no public_key)");

    BOOL_CHECK(vsc_buffer_len(credentials_public_key) <= VS_MESSENGER_VIRGIL_KEY_SZ_MAX,
               "Failed to parse credentials (public key too big)");

    credentials_public_key_id =
            vssc_json_object_get_binary_value_new(credentials_json, k_brain_key_JSON_PUBLIC_KEY_ID, &core_sdk_error);
    BOOL_CHECK(!vssc_error_has_error(&core_sdk_error), "Failed to parse credentials (no public_key_id)");

    BOOL_CHECK(VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ == vsc_buffer_len(credentials_public_key_id),
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

    res = VS_CODE_OK;

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

    return res;
}

/******************************************************************************/
