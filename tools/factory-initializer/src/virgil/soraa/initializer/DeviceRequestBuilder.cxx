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

#include <virgil/iot/initializer/DeviceRequestBuilder.h>
#include <virgil/sdk/client/models/RawSignature.h>
#include <virgil/sdk/client/models/RawCardContent.h>
#include <virgil/sdk/cards/CardManager.h>
#include <virgil/crypto/foundation/VirgilHash.h>

using virgil::soraa::initializer::DeviceRequestBuilder;
using virgil::soraa::initializer::PublicKeyProviderInterface;
using virgil::soraa::initializer::DeviceInfo;
using virgil::sdk::client::models::RawCardContent;
using virgil::sdk::client::models::RawSignature;
using virgil::sdk::cards::ModelSigner;
using virgil::sdk::crypto::Crypto;
using virgil::crypto::foundation::VirgilHash;

DeviceRequestBuilder::DeviceRequestBuilder(std::shared_ptr<Crypto> crypto,
                                           std::shared_ptr<DeviceInfoProviderInterface> deviceInfoProvider,
                                           std::shared_ptr<PublicKeyProviderInterface> publicKeyProvider,
                                           std::shared_ptr<SignerInterface> signer)
    : crypto_(std::move(crypto)), deviceInfoProvider_(std::move(deviceInfoProvider)),
      publicKeyProvider_(std::move(publicKeyProvider)), signer_(std::move(signer)) {
}

std::string DeviceRequestBuilder::buildRequest() {
    const auto &deviceInfo = deviceInfoProvider_->deviceInfo();

    auto cardContent = RawCardContent(deviceInfo.identity(), publicKeyProvider_->publicKey(), time(0));
    auto rawCard = RawSignedModel(cardContent.snapshot());

    auto extraContent = VirgilByteArrayUtils::stringToBytes(deviceInfo.getAllDeviceInfo());
    auto combinedSnapshot = rawCard.contentSnapshot();
    VirgilByteArrayUtils::append(combinedSnapshot, extraContent);

    auto dataHash = VirgilHash(VirgilHashAlgorithm::SHA256).hash(combinedSnapshot);
    auto signature = signer_->sign(dataHash);

    auto rawSignature = RawSignature("self", signature, extraContent);
    rawCard.addSignature(rawSignature);

    return rawCard.exportAsBase64EncodedString();
}

std::string DeviceRequestBuilder::getDeviceInfo() {
    return deviceInfoProvider_->payloadJson();
}
