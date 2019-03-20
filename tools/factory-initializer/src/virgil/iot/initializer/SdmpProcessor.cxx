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

#include <cstring>
#include <virgil/iot/initializer/SdmpProcessor.h>
#include <virgil/iot/initializer/NetRequestSender.h>
#include <externals/json.hpp>
#include <virgil/iot/initializer/SdmpBuild.h>

using virgil::soraa::initializer::SdmpProcessor;
using service_PRVS_provision_info_t = virgil::soraa::initializer::service_PRVS_provision_info_t;
using json = nlohmann::json;

const std::string SdmpProcessor::kBaseAddr("0.0.0.0");
const std::string SdmpProcessor::kServiceName("prvs");

const std::string SdmpProcessor::kSetData("iSET");
const std::string SdmpProcessor::kGetData("iGET");

const std::string SdmpProcessor::kSetRecKey1("PBR1");
const std::string SdmpProcessor::kSetRecKey2("PBR2");
const std::string SdmpProcessor::kSetAuthKey1("PBA1");
const std::string SdmpProcessor::kSetAuthKey2("PBA2");
const std::string SdmpProcessor::kSetTLKey1("PBT1");
const std::string SdmpProcessor::kSetTLKey2("PBT2");
const std::string SdmpProcessor::kSetFWKey1("PBF1");
const std::string SdmpProcessor::kSetFWKey2("PBF2");

const std::string SdmpProcessor::kSaveActionParam("ASAV");
const std::string SdmpProcessor::kDeviceInfoParam("DEVI");
const std::string SdmpProcessor::kDeviceSignatureParam("SGNP");
const std::string SdmpProcessor::kSignActionParam("ASGN");
const std::string SdmpProcessor::kDiscoveryNotInitedDevicesParam("DNID");

const std::string SdmpProcessor::kSetTLHeader("_TLH");
const std::string SdmpProcessor::kSetTLChunks("_TLC");
const std::string SdmpProcessor::kSetTLFooter("_TLF");

SdmpProcessor::SdmpProcessor(const ProvisioningInfo & provisioningInfo,
                             std::string addr,
                             DeviceType type,
                             std::shared_ptr<SignerInterface> deviceSigner) :
deviceSigner_(std::move(deviceSigner)), addr_(addr), deviceType_(type) {
    if (provisioningInfo.trustListOnly()) {
        if (!setTrustList(provisioningInfo)) throw std::runtime_error("Can't set Trust List");

        std::cout << "OK: Trust List set successfully. " << std::endl;
    } else {
        if (!provisioningInfo.createCardOnly()) {
            if (!initDevice()) throw std::runtime_error("Can't initialize device");
            if (!setKeys(provisioningInfo)) throw std::runtime_error("Can't set keys to device");
            if (!signDevice()) throw std::runtime_error("Can't sign device");
        }
        if (!getProvisionInfo()) throw std::runtime_error("Can't get provision info from device");

        std::cout << "OK: Device initialization done successfully. " << std::endl;
    }
}

std::vector<virgil::soraa::initializer::SOneDev_t> SdmpProcessor::discoverDevices() {
    std::string request = kServiceName + " "
    + kBaseAddr + " "
    + kGetData + " "
    + kDiscoveryNotInitedDevicesParam;

    const auto fullResponse = NetRequestSender::netRequestMultiple(request);

    std::vector<SOneDev_t> result;

    std::stringstream ss(fullResponse);
    std::string response;
    while (std::getline(ss, response, '\n')) {
        if (isOk(response)) {
            try {
                auto jsonData = json::parse(response);
                const std::string responseData = jsonData["ethernet"]["sdmp"]["content"]["ack"]["message_data"]["data"]["val"];

                VirgilByteArray ba = VirgilBase64::decode(responseData);
                auto res = reinterpret_cast <service_PRVS_DNID_t *> (ba.data());

                std::string macAddr;
                for (auto macPart: res->mac) {
                    auto macPartArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(&macPart, 1);
                    macAddr += VirgilByteArrayUtils::bytesToHex(macPartArray) + ":";
                }
                macAddr.pop_back();

                DeviceType type;
                switch (res->deviceType) {
                    case dev_unknown: type = DeviceType::Unknown; break;
                    case dev_lamp: type = DeviceType::Lamp; break;
                    case dev_snap: type = DeviceType::Snap; break;
                    case dev_gateway: type = DeviceType::Gateway; break;
                    case dev_ncm: type = DeviceType::NCM; break;
                    default:
                        const auto what(std::string("Wrong data in response \n" + response));
                        throw std::runtime_error(what);
                }

                SOneDev_t devInfo = {
                        macAddr,
                        type
                };

                std::cout << devInfo.macAddr << "   " << std::endl;

                result.push_back(devInfo);
            } catch(...) {
                const auto what(std::string("Wrong data in response \n" + response));
                throw std::runtime_error(what);
            }
        }
    }

    return result;
}

bool SdmpProcessor::initDevice() {
    const auto response = NetRequestSender::netRequest(createRequest(kSetData, kSaveActionParam), 20);

    if (isOk(response)) {
        try {
            auto jsonData = json::parse(response);
            const std::string responseData = jsonData["ethernet"]["sdmp"]["content"]["ack"]["message_data"]["data"]["val"];

            VirgilByteArray ba = VirgilBase64::decode(responseData);

            auto res = reinterpret_cast <service_PRVS_own_key_signed_t *> (ba.data());

            auto dataToVerify = VirgilByteArray(ba.begin(), ba.begin() + sizeof(service_PRVS_own_key_t));
            auto keyTiny = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->key.tiny, 64);
            auto keyFull = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->key.full, res->key.full_sz);
            auto signature = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->signature.val, res->signature.val_sz);

            if (!deviceSigner_->verify(dataToVerify,
                                       signature,
                                       keyFull)) {
                const auto what(std::string("Wrong key value of device in PRVS:ASAV \n" + response));
                throw std::runtime_error(what);
            }

            devicePublicKeyTiny_ = keyTiny;

            return true;
        } catch(...) {
            const auto what(std::string("Wrong data in response \n" + response));
            throw std::runtime_error(what);
        }
    }

    return false;
}

bool SdmpProcessor::setTrustList(const ProvisioningInfo & provisioningInfo) const {
    const auto _setTlHeader(createRequest(kSetData,
                                          kSetTLHeader,
                                          VirgilBase64::encode(provisioningInfo.tlHeader())));
    const auto _setTlFooter(createRequest(kSetData,
                                          kSetTLFooter,
                                          VirgilBase64::encode(provisioningInfo.tlFooter())));

    std::string  _setTLChunks[provisioningInfo.tlChunksAmount()];

    for (uint16_t i = 0; i < provisioningInfo.tlChunksAmount();i++) {
        _setTLChunks[i] = createRequest(kSetData,
                                        kSetTLChunks,
                                        VirgilBase64::encode(provisioningInfo.tlChunk(i)));
    }

    try {
        if (isOk(NetRequestSender::netRequest(_setTlHeader))) {

            for (uint16_t i = 0; i < provisioningInfo.tlChunksAmount(); i++) {
                if (!isOk(NetRequestSender::netRequest(_setTLChunks[i]))) {
                    return false;
                }
            }

            if (!isOk(NetRequestSender::netRequest(_setTlFooter, 30))) {
                return false;
            }

            return true;
        }
    } catch (...) {
        std::cerr << "ERROR: Can't set Trust List" << std::endl;
    }

    return false;
}

bool SdmpProcessor::setKeys(const ProvisioningInfo & provisioningInfo) const {

    const auto _setAuthPublicKey1(createRequest(kSetData,
                                                kSetAuthKey1,
                                                VirgilBase64::encode(provisioningInfo.authPubKey1())));
    const auto _setAuthPublicKey2(createRequest(kSetData,
                                                kSetAuthKey2,
                                                VirgilBase64::encode(provisioningInfo.authPubKey2())));
    const auto _setRecPublicKey1(createRequest( kSetData,
                                                kSetRecKey1,
                                                VirgilBase64::encode(provisioningInfo.recPubKey1())));
    const auto _setRecPublicKey2(createRequest( kSetData,
                                                kSetRecKey2,
                                                VirgilBase64::encode(provisioningInfo.recPubKey2())));
    const auto _setTlPublicKey1(createRequest( kSetData,
                                               kSetTLKey1,
                                               VirgilBase64::encode(provisioningInfo.tlPubKey1())));
    const auto _setTlPublicKey2(createRequest( kSetData,
                                               kSetTLKey2,
                                               VirgilBase64::encode(provisioningInfo.tlPubKey2())));
    const auto _setFWPublicKey1(createRequest( kSetData,
                                               kSetFWKey1,
                                               VirgilBase64::encode(provisioningInfo.fwPubKey1())));
    const auto _setFWPublicKey2(createRequest( kSetData,
                                               kSetFWKey2,
                                               VirgilBase64::encode(provisioningInfo.fwPubKey2())));


    try {

        if (isOk(NetRequestSender::netRequest(_setRecPublicKey1))
            && isOk(NetRequestSender::netRequest(_setRecPublicKey2))
            && isOk(NetRequestSender::netRequest(_setAuthPublicKey1))
            && isOk(NetRequestSender::netRequest(_setAuthPublicKey2))
            && isOk(NetRequestSender::netRequest(_setTlPublicKey1))
            && isOk(NetRequestSender::netRequest(_setTlPublicKey2))
            && isOk(NetRequestSender::netRequest(_setFWPublicKey1))
            && isOk(NetRequestSender::netRequest(_setFWPublicKey2))
            && setTrustList(provisioningInfo)) {

            return true;
        }
    } catch (...) {
        std::cerr << "ERROR: Can't initialize device" << std::endl;
    }
    
    return false;
}

bool SdmpProcessor::signDevice() const {
    auto signatureVal = deviceSigner_->sign(devicePublicKeyTiny_);

    if (signatureVal.empty()) {
        std::cerr << "ERROR: signature empty" << std::endl;
        return false;
    }

    if (!deviceSigner_->verify(devicePublicKeyTiny_,
                              signatureVal,
                              deviceSigner_->publicKeyFull())) {
        std::cerr << "ERROR: signature is wrong" << std::endl;
        return false;
    }

    std::cout << "Public key: " << VirgilBase64::encode(deviceSigner_->publicKeyFull()) << std::endl;
    std::cout << "Signer ID: " << deviceSigner_->signerId() << std::endl;
    std::cout << "Device key: " << VirgilBase64::encode(devicePublicKeyTiny_) << std::endl;
    std::cout << "Signature: " << VirgilBase64::encode(signatureVal) << std::endl;
    
    VirgilByteArray data;
    data.resize(sizeof(service_PRVS_full_signature_t) + signatureVal.size());
    auto signature = reinterpret_cast<service_PRVS_full_signature_t *>(data.data());
    signature->id = deviceSigner_->signerId();
    signature->val_sz = signatureVal.size();
    memcpy(signature->val, signatureVal.data(), signature->val_sz);

    const auto _signRequest(createRequest(kSetData,
                                          kDeviceSignatureParam,
                                          VirgilBase64::encode(data)));
    return isOk(NetRequestSender::netRequest(_signRequest));
}

bool SdmpProcessor::getProvisionInfo() {
    
    const auto response = NetRequestSender::netRequest(createRequest(kGetData, kDeviceInfoParam));
    
    if (isOk(response)) {
        try {
            auto jsonData = json::parse(response);
            const std::string responseData = jsonData["ethernet"]["sdmp"]["content"]["ack"]["message_data"]["data"]["val"];

            VirgilByteArray ba = VirgilBase64::decode(responseData);
            auto res = reinterpret_cast <service_PRVS_provision_info_signed_t *> (ba.data());

            auto dataToVerify = VirgilByteArray(ba.begin(), ba.begin() + sizeof(service_PRVS_provision_info_t));
            auto keyTiny = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->info.own_key.tiny, 64);
            auto keyFull = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->info.own_key.full, res->info.own_key.full_sz);
            auto signature = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->signature.val, res->signature.val_sz);

            if (!deviceSigner_->verify(dataToVerify,
                                       signature,
                                       keyFull)) {
                const auto what(std::string("Wrong data value of device in PRVS:DEVI \n" + response));
                throw std::runtime_error(what);
            }
            
            deviceID_ = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->info.udid_of_device, 32);
            devicePublicKey_ = keyFull;
            devicePublicKeyTiny_ = keyTiny;
            deviceMacAddr_ = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->info.mac, 6);
            signerID_ = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->info.signature.signer_id.val, PUBKEY_TINY_ID_SZ);
            signature_ = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->info.signature.val, SIGNATURE_SZ);
            manufacturer_ = res->info.manufacturer;
            model_ = res->info.model;
            
            return true;
        } catch(...) {
            const auto what(std::string("Wrong data in response \n" + response));
            throw std::runtime_error(what);
        }
    }
    
    return false;
}

std::string SdmpProcessor::createRequest(const std::string & action,
                                         const std::string & param,
                                         const std::string & value) const {
    VirgilByteArray request;

    request.resize(1);
    request.data()[0] = static_cast<uint8_t >(deviceType_);

    if (!value.empty()) {
        auto currentData = VirgilBase64::decode(value);
        request.resize(request.size() + currentData.size());
        memcpy(request.data() + 1, currentData.data(), currentData.size());
    }

    std::stringstream stream;
    
    stream
    << kServiceName << " "
    << addr_ << " "
    << action << " "
    << param << " "
    << VirgilBase64::encode(request);
    
    return stream.str();
}

bool SdmpProcessor::isOk(const std::string & netResponse) {
    try {
        auto jsonData = json::parse(netResponse);
        const int32_t result = jsonData["ethernet"]["sdmp"]["content"]["ack"]["error"];
#if 0
        std::cout << "  returned " << result << std::endl;
#endif
        return 0 == result;
    } catch(...) {
        std::cout << "Incorrect response from device" << std::endl << netResponse << std::endl;
    }

    return false;
}

VirgilByteArray SdmpProcessor::deviceID() const {
    return deviceID_;
}

VirgilByteArray SdmpProcessor::deviceMacAddr() const {
    return deviceMacAddr_;
}

VirgilByteArray SdmpProcessor::devicePublicKey() const {
    return devicePublicKey_;
}

VirgilByteArray SdmpProcessor::devicePublicKeyTiny() const {
    return devicePublicKeyTiny_;
}

VirgilByteArray SdmpProcessor::signerId() const {
    return signerID_;
}

VirgilByteArray SdmpProcessor::signature() const {
    return signature_;
}

uint32_t SdmpProcessor::manufacturer() const {
    return manufacturer_;
}

uint32_t SdmpProcessor::model() const {
    return model_;
}

virgil::soraa::initializer::DeviceType SdmpProcessor::deviceType() const {
    return deviceType_;
}

VirgilByteArray SdmpProcessor::signDataInDevice(const VirgilByteArray & data) const {
    
    const auto _signRequest(createRequest(kSetData,
                                          kSignActionParam,
                                          VirgilBase64::encode(data)));
    
    const auto response = NetRequestSender::netRequest(_signRequest);
    
    if (isOk(response)) {
        try {
            auto jsonData = json::parse(response);
            const std::string responseData = jsonData["ethernet"]["sdmp"]["content"]["ack"]["message_data"]["data"]["val"];
            
            return VirgilBase64::decode(responseData);
        } catch(...) {
            const auto what(std::string("Wrong data in response \n" + response));
            throw std::runtime_error(what);
        }
    }
    
    return VirgilByteArray();
}
