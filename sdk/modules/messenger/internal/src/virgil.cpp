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

// Module variables
static bool _is_initialized = false;
static bool _is_credentials_ready = false;
static std::shared_ptr<Crypto> crypto;
static vs_messenger_virgil_user_creds_t _creds = {{0}, 0, {0}, 0, {0}};
static char *_service_base_url = NULL;
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
    } else {
        Connection::setCA("");
    }

    // Check input parameters
    CHECK_NOT_ZERO_RET(service_base_url && service_base_url[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    crypto = std::make_shared<Crypto>();
    _service_base_url = strdup(service_base_url);

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
extern "C" DLL_PUBLIC vs_status_e
vs_messenger_virgil_logout(void) {
    VS_IOT_ASSERT(_is_initialized);
    crypto = nullptr;
    free(_service_base_url);
    _service_base_url = NULL;
    _is_credentials_ready = false;
    _is_initialized = false;
    _is_virgil_token_ready = false;
    return VS_CODE_OK;
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
