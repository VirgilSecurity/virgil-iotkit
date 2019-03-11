/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/soraa/registrator/LampRegistrator.h>
#include <virgil/sdk/client/CardClient.h>
#include <virgil/sdk/client/models/RawCardContent.h>
#include <virgil/sdk/cards/ModelSigner.h>
#include <virgil/sdk/cards/CardManager.h>
#include <virgil/sdk/jwt/JwtGenerator.h>
#include <virgil/sdk/jwt/providers/GeneratorJwtProvider.h>
#include <virgil/sdk/util/JsonUtils.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::crypto::keys::KeyPair;
using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::crypto::keys::PublicKey;
using virgil::soraa::registrator::LampRegistrator;
using virgil::sdk::client::CardClient;
using virgil::sdk::client::networking::errors::Error;
using virgil::sdk::client::models::RawCardContent;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::cards::ModelSigner;
using virgil::sdk::cards::CardManager;
using virgil::sdk::jwt::Jwt;
using virgil::sdk::jwt::JwtGenerator;
using virgil::sdk::util::JsonUtils;
using nlohmann::json;
using virgil::sdk::VirgilByteArray;

LampRegistrator::LampRegistrator(std::shared_ptr<RequestProviderInterface> requestProvider,
                                 const CardsServiceInfo & cardsServiceInfo,
                                 bool isAddSerialNumber)
: requestProvider_(std::move(requestProvider)), cardsServiceInfo_(std::move(cardsServiceInfo)) {
    isAddSerialNumber_ = isAddSerialNumber;
}

void LampRegistrator::registerLamps() {

    auto crypto = std::make_shared<Crypto>();
    auto iotPrivateKey = crypto->importPrivateKey(cardsServiceInfo_.iotPrivateKey());
    auto apiPrivateKey = crypto->importPrivateKey(cardsServiceInfo_.apiPrivateKey());
    auto jwtGenerator = JwtGenerator(apiPrivateKey, cardsServiceInfo_.apiKeyID(), crypto, cardsServiceInfo_.appID(), 5 * 60);

    auto cardClient = (isAddSerialNumber_) ? CardClient(cardsServiceInfo_.baseCardServiceUrl()) : CardClient();

    while (requestProvider_->hasData()) {

        std::cout << "Processing" << std::endl;

        auto requestStr = requestProvider_->getData();
        auto rawCard = RawSignedModel::importFromBase64EncodedString(requestStr);

        std::string jwtTokenString("");

        auto contentSnapshot = json::parse(VirgilByteArrayUtils::bytesToString(rawCard.contentSnapshot()));
        auto identity = contentSnapshot["identity"];
        auto jwtToken = jwtGenerator.generateToken(identity);

        if(isAddSerialNumber_) {
            auto serialNumber = requestProvider_->getSerialNumbers();
            auto signer = ModelSigner(crypto);
            signer.sign(rawCard,std::string("iot_registrator"),iotPrivateKey,{{"visible_serial_number",serialNumber}});
        } else {
            jwtTokenString = jwtToken.stringRepresentation();
        }

        try {
            auto future = cardClient.publishCard(rawCard, jwtTokenString);
            auto publishedRawCard = future.get();
            auto publishedCard = CardManager::parseCard(publishedRawCard, crypto);

            std::cout << "Output: " << publishedCard.identity() << " " << publishedCard.createdAt() << " " << publishedCard.version() << std::endl;
        }
        catch (Error& error) {
            std::cout << error.errorMsg() << std::endl;
            continue;
        }

    }

    std::cout << "No more data" << std::endl;
}
