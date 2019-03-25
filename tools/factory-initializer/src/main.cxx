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

#include <memory>
#include <vector>
#include <iostream>

#include <virgil/iot/initializer/AssemblyLineProcessor.h>
#include <virgil/iot/initializer/DeviceRequestBuilder.h>
#include <virgil/iot/initializer/SingleFileEncryptedPersistenceManager.h>
#include <virgil/iot/initializer/ParamsCommadLine.h>
#include <virgil/iot/initializer/Filesystem.h>
#include <virgil/iot/initializer/SdmpBuild.h>
#include <virgil/iot/initializer/SingleFileEncryptedPersistenceManager.h>
#include <virgil/iot/initializer/SdmpDeviceInfoProvider.h>
#include <virgil/iot/initializer/SdmpSigner.h>
#include <virgil/iot/initializer/DeviceRequestBuilder.h>
#include <virgil/iot/initializer/AssemblyLineProcessor.h>
#include <virgil/iot/initializer/ProvisioningInfo.h>
#include <virgil/iot/initializer/VirgilCryptoSigner.h>

using virgil::soraa::initializer::AssemblyLineProcessor;
using virgil::soraa::initializer::DeviceRequestBuilder;
using virgil::soraa::initializer::SingleFileEncryptedPersistenceManager;
using virgil::soraa::initializer::ParamsCommadLine;
using virgil::soraa::initializer::Filesystem;
using virgil::soraa::initializer::SingleFileEncryptedPersistenceManager;
using virgil::soraa::initializer::SdmpDeviceInfoProvider;
using virgil::soraa::initializer::SdmpSigner;
using virgil::soraa::initializer::DeviceRequestBuilder;
using virgil::soraa::initializer::AssemblyLineProcessor;
using virgil::soraa::initializer::DeviceType;
using virgil::soraa::initializer::VirgilCryptoSigner;
using virgil::soraa::initializer::AtmelCryptoSigner;
using virgil::sdk::crypto::Crypto;

int main (int argc, char *argv[]) {

    Filesystem::init();

    auto params = std::make_shared<ParamsCommadLine>(argc, argv);
    auto crypto = std::make_shared<Crypto>();

    auto fileTransmitPrivateKey = crypto->importPrivateKey(params->fileEncryptionPrivateKey(),
                                                           params->fileEncryptionPrivateKeyPassword());

    auto fileRecipientsPublicKeys = std::vector<virgil::sdk::crypto::keys::PublicKey>();
    fileRecipientsPublicKeys.push_back(crypto->importPublicKey(params->fileRecipientPublicKey()));

    // Persistence for Virgil Cards Requests
    auto persistenceManager = SingleFileEncryptedPersistenceManager(params->exportFile(),
                                                                    crypto,
                                                                    fileTransmitPrivateKey,
                                                                    fileRecipientsPublicKeys);

    // Persistence for Device Info
    auto deviceInfoPersistenceManager = SingleFileEncryptedPersistenceManager(params->deviceInfoFile(),
                                                                              crypto,
                                                                              fileTransmitPrivateKey,
                                                                              fileRecipientsPublicKeys);

    std::shared_ptr<SignerInterface> deviceSigner;

    // Soraa device initialization
    auto keyData = virgil::soraa::initializer::Filesystem::loadFile(params->factoryPrivateKey());
    auto deviceSignPrivateKey = virgil::sdk::crypto::Crypto().importPrivateKey(keyData);
    deviceSigner = std::make_shared<VirgilCryptoSigner>(crypto, deviceSignPrivateKey);

    vs_sdmp_prvs_dnid_list_t devices = SdmpProcessor::discoverDevices();

    std::cout << "Got " + std::to_string(devices.count) + " devices :" << std::endl << std::endl;


    for (int i = 0; i < devices.count; i++) {

        std::cout << "Device type : " << std::to_string(devices.elements[i].device_type) << std::endl;
        std::cout << "Device MAC  : ";
        for (int j = 0; j < ETH_ADDR_LEN; j++) {
            if (j) {
                std::cout << ":";
            }

            std::cout << std::setfill ('0') << std::setw(sizeof(uint8_t)*2)
                      << std::hex << static_cast<int> (devices.elements[i].mac_addr.bytes[j]);
        }
        std::cout << std::endl;

        auto sdmpProcessor = std::make_shared<SdmpProcessor>(params->provisioningInfo(),
                                                             devices.elements[i],
                                                             deviceSigner);

        if (!params->provisioningInfo().trustListOnly()) {
            auto deviceInfoProvider = std::make_shared<SdmpDeviceInfoProvider>(params->provisioningInfo(), sdmpProcessor);
            auto publicKeyProvider = std::make_shared<SdmpPublicKeyProvider>(sdmpProcessor);
            auto signer = std::make_shared<SdmpSigner>(sdmpProcessor);

            // Get all things needed for creating request
            auto deviceRequestBuilder = DeviceRequestBuilder(crypto, deviceInfoProvider, publicKeyProvider, signer);

//            // Create request and persist to persistence manager
            AssemblyLineProcessor::processDevice(deviceRequestBuilder, persistenceManager, deviceInfoPersistenceManager);
        }
    }

    return 0;
}
