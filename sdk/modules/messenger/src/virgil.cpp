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

#include <private/virgil.h>

using namespace VirgilIoTKit;

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/CardClient.h>

#include <virgil/sdk/client/models/RawCardContent.h>
#include <virgil/sdk/client/networking/Request.h>
#include <virgil/sdk/client/networking/Response.h>
#include <virgil/sdk/client/networking/Connection.h>
#include <virgil/sdk/cards/ModelSigner.h>
#include <virgil/sdk/cards/CardManager.h>
#include <virgil/sdk/cards/verification/VirgilCardVerifier.h>
#include <virgil/sdk/VirgilSdkError.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/serialization/JsonSerializer.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/crypto/VirgilByteArray.h>

#include <stdio.h>
#include <string.h>

using nlohmann::json;
using virgil::sdk::VirgilBase64;
using virgil::sdk::cards::Card;
using virgil::sdk::cards::CardManager;
using virgil::sdk::cards::ModelSigner;
using virgil::sdk::cards::verification::VirgilCardVerifier;
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
using virgil::sdk::util::JsonUtils;

using virgil::crypto::bytes2hex;
using virgil::crypto::hex2bytes;
using virgil::crypto::str2bytes;

#include <iostream>

static const char *_service_base_url = "https://messenger-stg.virgilsecurity.com";

static const char *_virgil_jwt_endpoint = "/virgil-jwt/";
static const char *_ejabberd_jwt_endpoint = "/ejabberd-jwt/";
static const char *_sign_up_endpoint = "/signup/";

static std::shared_ptr<Crypto> crypto;

static const char *_identity = NULL;
static const uint8_t *_pubkey = NULL;
static size_t _pubkey_sz = 0;
static const uint8_t *_privkey = NULL;
static size_t _privkey_sz = 0;
static const uint8_t *_card = NULL;
static size_t _card_sz = 0;
static char *_card_id = NULL;

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_virgil_init(void) {
    crypto = std::make_shared<Crypto>();
    return VS_CODE_OK;
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_virgil_sign_in(const char *identity,
                            const uint8_t *pubkey,
                            size_t pubkey_sz,
                            const uint8_t *privkey,
                            size_t privkey_sz,
                            const uint8_t *card,
                            size_t card_sz) {

    _identity = identity;
    _pubkey = pubkey;
    _pubkey_sz = pubkey_sz;
    _privkey = privkey;
    _privkey_sz = privkey_sz;
    _card = card;
    _card_sz = card_sz;

    auto rawCard = JsonDeserializer<RawSignedModel>::fromJsonString(reinterpret_cast<const char *>(card));
    auto parsedCard = CardManager::parseCard(rawCard, crypto);
    _card_id = strdup(parsedCard.identifier().c_str());

    return VS_CODE_OK;
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_virgil_sign_up(const char *identity,
                            uint8_t *pubkey,
                            size_t pubkey_buf_sz,
                            size_t *pubkey_sz,
                            uint8_t *privkey,
                            size_t privkey_buf_sz,
                            size_t *privkey_sz,
                            uint8_t *card,
                            size_t card_buf_sz,
                            size_t *card_sz) {

    auto identityStd = std::string(identity);

    ModelSigner modelSigner(crypto);

    auto keyPair = crypto->generateKeyPair();
    auto publicKeyData = crypto->exportPublicKey(keyPair.publicKey());

    RawCardContent content(identityStd, publicKeyData, std::time(0));
    auto snapshot = content.snapshot();

    RawSignedModel rawCard(snapshot);
    modelSigner.selfSign(rawCard, keyPair.privateKey());

    auto exportedRawCard = rawCard.exportAsJson();

    json requestJSON = {{"raw_card", JsonSerializer<RawSignedModel>::toJson(rawCard)}};

    auto httpRequest = Request();

    httpRequest.baseAddress(_service_base_url)
            .endpoint(_sign_up_endpoint)
            .contentType("application/json")
            .body(requestJSON.dump())
            .post();

    Connection connection;
    Response response = connection.send(httpRequest);

    if (response.fail()) {
        std::cout << response.statusCodeRaw() << " : " << response.body() << std::endl;
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    auto responseJSON = json::parse(response.body());

    auto cardJSON = responseJSON["virgil_card"].dump();
    auto readyCard = JsonDeserializer<RawSignedModel>::fromJsonString(cardJSON);
    auto parsedCard = CardManager::parseCard(rawCard, crypto);
    _card_id = strdup(parsedCard.identifier().c_str());

    auto cardContent = RawCardContent::parse(readyCard.contentSnapshot());
    _card_id = strdup(cardContent.identity().c_str());

    // Prepare result
    auto privateKeyData = crypto->exportPrivateKey(keyPair.privateKey());
    auto cardData = str2bytes(cardJSON);

    *pubkey_sz = 0;
    *privkey_sz = 0;
    *card_sz = 0;

    if (publicKeyData.size() <= pubkey_buf_sz) {
        *pubkey_sz = publicKeyData.size();
        memcpy(pubkey, publicKeyData.data(), *pubkey_sz);
    }

    if (privateKeyData.size() <= privkey_buf_sz) {
        *privkey_sz = privateKeyData.size();
        memcpy(privkey, privateKeyData.data(), *privkey_sz);
    }

    if (cardData.size() <= card_buf_sz) {
        *card_sz = cardData.size();
        memcpy(card, cardData.data(), *card_sz);
    }

    // Print results
    std::cout << "Public key  : " << VirgilBase64::encode(publicKeyData) << std::endl;
    std::cout << "Private key : " << VirgilBase64::encode(privateKeyData) << std::endl;
    std::cout << "Card        : " << VirgilBase64::encode(cardData) << std::endl;

    return VS_CODE_OK;
}

// private func makeAuthHeader(for identity: String) throws -> [String: String] {
// let localKeyManager = try LocalKeyManager(identity: identity, crypto: self.crypto)
//
// let user = try localKeyManager.retrieveUserData()
//
// let stringToSign = "\(user.card.identifier).\(Int(Date().timeIntervalSince1970))"
//
// guard let dataToSign = stringToSign.data(using: .utf8) else {
// throw Error.stringToDataFailed
//}
//
// let signature = try crypto.generateSignature(of: dataToSign, using: user.keyPair.privateKey)
//
// let authHeader = "Bearer " + stringToSign + "." + signature.base64EncodedString()
//
// return ["Authorization": authHeader]
//}
/******************************************************************************/
static vs_status_e
_get_token(const char *endpoint, char *token, size_t token_buf_sz) {

    // Create Auth header
    unsigned long unixTime = time(NULL);
    auto signStr = std::string(_card_id) + "." + std::to_string(static_cast<unsigned long>(time(NULL)));
    auto privateKey = crypto->importPrivateKey(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(_privkey, _privkey_sz));
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

    // Parse response
    if (response.fail()) {
        std::cout << response.statusCodeRaw() << " : " << response.body() << std::endl;
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    auto responseJSON = json::parse(response.body());

    std::string tokenStd = responseJSON["token"].dump();

    if (tokenStd.length() < token_buf_sz) {
        strcpy(token, tokenStd.c_str());
    }

    // Print results
    std::cout << endpoint << " : " << token << std::endl;

    return VS_CODE_OK;
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_virgil_get_token(char *token, size_t token_buf_sz) {
    return _get_token(_virgil_jwt_endpoint, token, token_buf_sz);
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_virgil_get_xmpp_pass(char *pass, size_t pass_buf_sz) {
    return _get_token(_ejabberd_jwt_endpoint, pass, pass_buf_sz);
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_virgil_logout(void) {
    crypto = nullptr;
    free(_card_id);
    return VS_CODE_OK;
}

/******************************************************************************/