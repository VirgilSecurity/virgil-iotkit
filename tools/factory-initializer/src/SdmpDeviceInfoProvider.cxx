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

#include <virgil/iot/initializer/SdmpDeviceInfoProvider.h>
#include <virgil/sdk/crypto/Crypto.h>
#include <externals/json.hpp>

using virgil::soraa::initializer::SdmpDeviceInfoProvider;
using virgil::soraa::initializer::DeviceInfo;
using virgil::sdk::VirgilBase64;
using namespace virgil::crypto;
using json = nlohmann::json;

const std::string SdmpDeviceInfoProvider::kIdentityType = "id";
const std::string SdmpDeviceInfoProvider::kDeviceTypeLamp = "Soraa Lamp";
const std::string SdmpDeviceInfoProvider::kDeviceTypeSnap = "Soraa Snap";
const std::string SdmpDeviceInfoProvider::kDeviceTypeGateway = "Soraa Gateway";
const std::string SdmpDeviceInfoProvider::kDeviceTypeNCM = "Soraa NCM";

SdmpDeviceInfoProvider::SdmpDeviceInfoProvider(const ProvisioningInfo & provisioningInfo,
                                               std::shared_ptr<SdmpProcessor> processor) :
provisioningInfo_(std::move(provisioningInfo)), deviceType_(processor->deviceType()), processor_(std::move(processor)) {
    
}

std::unordered_map<std::string, std::string> SdmpDeviceInfoProvider::payload() {
    std::unordered_map<std::string, std::string> payload;

    payload["manufacturer"] = _hex< uint32_t >(processor_->manufacturer());
    payload["model"] = _hex< uint32_t >(processor_->model());
    payload["mac"] = VirgilBase64::encode(processor_->deviceMacAddr());
    payload["serial"] = VirgilBase64::encode(processor_->deviceID());
    payload["publicKeyTiny"] = VirgilBase64::encode(processor_->devicePublicKeyTiny());
    payload["signerID"] = VirgilBase64::encode(processor_->signerId());
    payload["signature"] = VirgilBase64::encode(processor_->signature());

    return payload;
};

std::string SdmpDeviceInfoProvider::payloadJson() {
    json json(payload());

    return json.dump();
}

DeviceInfo SdmpDeviceInfoProvider::deviceInfo() {
    std::string deviceTypeStr;

    switch (deviceType_) {
        case DeviceType::Lamp: deviceTypeStr = kDeviceTypeLamp; break;
        case DeviceType::Snap: deviceTypeStr = kDeviceTypeSnap; break;
        case DeviceType::Gateway : deviceTypeStr = kDeviceTypeGateway; break;
        case DeviceType::NCM : deviceTypeStr = kDeviceTypeNCM; break;
        default:
            deviceTypeStr = "";
    }
    
    return DeviceInfo(bytes2hex(processor_->deviceID()),
                      kIdentityType,
                      deviceTypeStr,
                      std::to_string(processor_->model()),
                      payload());
}
