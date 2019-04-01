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
#include <iostream>
#include <virgil/iot/initializer/SdmpProcessor.h>
#include <virgil/iot/initializer/SdmpBuild.h>

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/PRVS.h>
#include <virgil/iot/initializer/hal/netif_plc_sim.h>

using virgil::soraa::initializer::SdmpProcessor;

const size_t SdmpProcessor::kDefaultWaitTimeMs = 200;

SdmpProcessor::SdmpProcessor(const ProvisioningInfo & provisioningInfo,
                             vs_sdmp_prvs_dnid_element_t deviceInfo,
                             std::shared_ptr<SignerInterface> deviceSigner) :
deviceSigner_(std::move(deviceSigner)), deviceInfo_(deviceInfo) {
    // Connect to PLC bus
    if (0 != vs_sdmp_init(vs_hal_netif_plc_sim())) {
        throw std::runtime_error(std::string("Can't start SDMP communication"));
    }

    if (0 != vs_sdmp_register_service(vs_sdmp_prvs_service())) {
        throw std::runtime_error(std::string("Can't register SDMP:PRVS service"));
    }

    //
    if (provisioningInfo.trustListOnly()) {
        if (!setTrustList(provisioningInfo)) throw std::runtime_error("Can't set Trust List");

        std::cout << "OK: Trust List set successfully. " << std::endl;
    } else {
        if (!provisioningInfo.createCardOnly()) {
            if (!initDevice()) throw std::runtime_error("Can't initialize device");
            if (!setKeys(provisioningInfo)) throw std::runtime_error("Can't set keys to device");
            if (!signDevice()) throw std::runtime_error("Can't sign device");
            if (!setTrustList(provisioningInfo)) throw std::runtime_error("Can't set Trust List");
        }
        if (!getProvisionInfo()) throw std::runtime_error("Can't get provision info from device");

        std::cout << "OK: Device initialization done successfully. " << std::endl;
    }
}

SdmpProcessor::~SdmpProcessor() {
    // Disconnect from PLC bus
    vs_sdmp_deinit();
}

vs_sdmp_prvs_dnid_list_t SdmpProcessor::discoverDevices() {
    vs_sdmp_prvs_dnid_list_t list;

    memset(&list, 0, sizeof(list));

    // Connect to PLC bus
    if (0 != vs_sdmp_init(vs_hal_netif_plc_sim())) {
        throw std::runtime_error(std::string("Can't start SDMP communication"));
    }

    if (0 != vs_sdmp_register_service(vs_sdmp_prvs_service())) {
        throw std::runtime_error(std::string("Can't register SDMP:PRVS service"));
    }

    vs_sdmp_prvs_uninitialized_devices(0, &list, kDefaultWaitTimeMs * 10);

    // Disconnect from PLC bus
    vs_sdmp_deinit();

    return list;
}

bool SdmpProcessor::initDevice() {
    vs_sdmp_pubkey_t asav_info;

    memset(&asav_info, 0 , sizeof(asav_info));

    if (0 != vs_sdmp_prvs_save_provision(0, &deviceInfo_.mac_addr, &asav_info, kDefaultWaitTimeMs)) {
        return false;
    }

    auto keyTiny = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(asav_info.pubkey, 64);

#if 0
    auto dataToVerify = VirgilByteArray(ba.begin(), ba.begin() + sizeof(service_PRVS_own_key_t));
    auto keyFull = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->key.full, res->key.full_sz);
    auto signature = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->signature.val, res->signature.val_sz);

    if (!deviceSigner_->verify(dataToVerify,
                               signature,
                               keyFull)) {
        const auto what(std::string("Wrong key value of device in PRVS:ASAV \n" + response));
        throw std::runtime_error(what);
    }
#endif
    devicePublicKeyTiny_ = keyTiny;

    return true;
}

bool SdmpProcessor::setTrustList(const ProvisioningInfo & provisioningInfo) const {

    // Set TL header
    std::cout << "Upload TrustList Header" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_TLH,
                              provisioningInfo.tlHeader().data(),
                              provisioningInfo.tlHeader().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }

    // Set TL chunks
    for (uint16_t i = 0; i < provisioningInfo.tlChunksAmount();i++) {
        std::cout << "Upload TrustList Chunk " << std::to_string(i) << std::endl;
        if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_TLC,
                                  provisioningInfo.tlChunk(i).data(),
                                  provisioningInfo.tlChunk(i).size(),
                                  kDefaultWaitTimeMs)) {
            return false;
        }
    }

    // Set TL footer
    std::cout << "Upload TrustList Footer" << std::endl;
    if (0 != vs_sdmp_prvs_finalize_tl(0, &deviceInfo_.mac_addr,
                                      provisioningInfo.tlFooter().data(),
                              provisioningInfo.tlFooter().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }

    return true;
}

bool SdmpProcessor::setKeys(const ProvisioningInfo & provisioningInfo) const {

    // Recovery public keys
    std::cout << "Upload Recovery key 1" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_PBR1,
                              provisioningInfo.recPubKey1().data(),
                              provisioningInfo.recPubKey1().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }

    std::cout << "Upload Recovery key 2" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_PBR2,
                              provisioningInfo.recPubKey2().data(),
                              provisioningInfo.recPubKey2().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }

    // Auth Public keys
    std::cout << "Upload Auth key 1" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_PBA1,
                              provisioningInfo.authPubKey1().data(),
                              provisioningInfo.authPubKey1().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }

    std::cout << "Upload Auth key 2" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_PBA2,
                              provisioningInfo.authPubKey2().data(),
                              provisioningInfo.authPubKey2().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }


    // Firmware public keys
    std::cout << "Upload Firmware key 1" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_PBF1,
                              provisioningInfo.fwPubKey1().data(),
                              provisioningInfo.fwPubKey1().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }

    std::cout << "Upload Firmware key 2" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_PBF2,
                              provisioningInfo.fwPubKey2().data(),
                              provisioningInfo.fwPubKey2().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }


    // TrustList Public keys
    std::cout << "Upload TrustList key 1" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_PBT1,
                              provisioningInfo.tlPubKey1().data(),
                              provisioningInfo.tlPubKey1().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }

    std::cout << "Upload TrustList key 2" << std::endl;
    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_PBT2,
                              provisioningInfo.tlPubKey2().data(),
                              provisioningInfo.tlPubKey2().size(),
                              kDefaultWaitTimeMs)) {
        return false;
    }
    
    return true;
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
    data.resize(sizeof(vs_sdmp_prvs_signature_t) + signatureVal.size());
    auto signature = reinterpret_cast<vs_sdmp_prvs_signature_t *>(data.data());
    signature->id = deviceSigner_->signerId();
    signature->val_sz = signatureVal.size();
    memcpy(signature->val, signatureVal.data(), signature->val_sz);

    if (0 != vs_sdmp_prvs_set(0, &deviceInfo_.mac_addr, VS_PRVS_SGNP,
                              (uint8_t *)signature,
                              sizeof(vs_sdmp_prvs_signature_t) + signature->val_sz,
                              kDefaultWaitTimeMs)) {
        return false;
    }

    return true;
}

bool SdmpProcessor::getProvisionInfo() {
    uint8_t devi_buf[512];
    vs_sdmp_prvs_devi_t *device_info = (vs_sdmp_prvs_devi_t *)devi_buf;

    memset(device_info, 0, sizeof(devi_buf));

    if (0 != vs_sdmp_prvs_device_info(0, &deviceInfo_.mac_addr, device_info, sizeof(devi_buf), kDefaultWaitTimeMs)) {
        return false;
    }

    auto keyFull = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(device_info->own_key.pubkey, device_info->own_key.pubkey_sz);
#if 0
    auto dataToVerify = VirgilByteArray(ba.begin(), ba.begin() + sizeof(service_PRVS_provision_info_t));
    auto keyTiny = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->info.own_key.tiny, 64);
    auto signature = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(res->signature.val, res->signature.val_sz);

    if (!deviceSigner_->verify(dataToVerify,
                               signature,
                               keyFull)) {
        const auto what(std::string("Wrong data value of device in PRVS:DEVI \n" + response));
        throw std::runtime_error(what);
    }

    devicePublicKeyTiny_ = keyTiny;
#endif
    devicePublicKey_ = keyFull;
    auto id = device_info->signature.id;
    signerID_ = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(&id, sizeof(id));
    signature_ = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(device_info->signature.val, device_info->signature.val_sz);


    deviceID_ = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(device_info->udid_of_device, 32);
    deviceMacAddr_ = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(device_info->mac.bytes, 6);
    manufacturer_ = device_info->manufacturer;
    model_ = device_info->model;

    return true;
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
    uint8_t signature[512];
    size_t signature_sz = 0;

    if (0 == vs_sdmp_prvs_sign_data(0, &deviceInfo_.mac_addr, data.data(), data.size(),
                                    signature, sizeof(signature), &signature_sz,
                                    kDefaultWaitTimeMs)) {
        return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(signature, signature_sz);
    }
    
    return VirgilByteArray();
}
