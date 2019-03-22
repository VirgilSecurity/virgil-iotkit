/**
 * Copyright (C) 2017 Virgil Security Inc.
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

#ifndef VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_SDMPPROCESSOR_H
#define VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_SDMPPROCESSOR_H

#include <string>
#include <vector>
#include <virgil/iot/initializer/ProvisioningInfo.h>
#include <virgil/iot/initializer/SignerInterface.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp/PRVS.h>

using virgil::soraa::initializer::ProvisioningInfo;
using virgil::soraa::initializer::SignerInterface;

#if 0
#define SIGNATURE_SZ      (64)
#define SALT_SZ           (32)
#define PUBKEY_TINY_SZ    (64)
#define PUBKEY_TINY_ID_SZ (2)
#define SERIAL_SIZE       (32)
#endif

namespace virgil {
namespace soraa {
    namespace initializer {
        
        class SdmpProcessor {
        public:
            SdmpProcessor(const ProvisioningInfo & provisioningInfo,
                          vs_sdmp_prvs_dnid_element_t deviceInfo,
                          std::shared_ptr<SignerInterface> deviceSigner);

            virtual ~SdmpProcessor() = default;
            
            VirgilByteArray deviceID() const;
            VirgilByteArray deviceMacAddr() const;
            VirgilByteArray devicePublicKey() const;
            VirgilByteArray devicePublicKeyTiny() const;
            VirgilByteArray signerId() const;
            VirgilByteArray signature() const;
            uint32_t manufacturer() const;
            uint32_t model() const;
            DeviceType deviceType() const;

            VirgilByteArray signDataInDevice(const VirgilByteArray & data) const;

            static vs_sdmp_prvs_dnid_list_t discoverDevices();
            
        private:
            bool initDevice();
            bool setTrustList(const ProvisioningInfo & provisioningInfo) const;
            bool setKeys(const ProvisioningInfo & provisioningInfo) const;

            bool signDevice() const;
            bool getProvisionInfo();

            vs_sdmp_prvs_dnid_element_t deviceInfo_;
            DeviceType deviceType_;

            std::shared_ptr<SignerInterface> deviceSigner_;
            VirgilByteArray deviceID_;
            VirgilByteArray devicePublicKey_;
            VirgilByteArray devicePublicKeyTiny_;
            VirgilByteArray deviceMacAddr_;
            VirgilByteArray signerID_;
            VirgilByteArray signature_;
            uint32_t manufacturer_;
            uint32_t model_;

            static const std::string kBaseAddr;

            static const std::string kServiceName;
            
            static const std::string kSetData;
            static const std::string kGetData;

            static const std::string kSetRecKey1;
            static const std::string kSetRecKey2;
            static const std::string kSetAuthKey1;
            static const std::string kSetAuthKey2;
            static const std::string kSetTLKey1;
            static const std::string kSetTLKey2;
            static const std::string kSetFWKey1;
            static const std::string kSetFWKey2;

            static const std::string kSetTLHeader;
            static const std::string kSetTLChunks;
            static const std::string kSetTLFooter;

            static const std::string kSerialNumberParam;
            static const std::string kModelParam;
            static const std::string kManufactureParam;
            static const std::string kPartsCountParam;
            static const std::string kPartParam;
            static const std::string kFirmwarePublicKeyParam;
            static const std::string kFirmwarePublicKeyAlternativeParam;
            static const std::string kDeviceVerificationPublicKeyParam;
            static const std::string kDeviceVerificationPublicKeyAlternativeParam;
            static const std::string kSaveActionParam;
            static const std::string kDeviceInfoParam;
            static const std::string kDeviceSignatureParam;
            static const std::string kSignActionParam;
            static const std::string kDiscoveryNotInitedDevicesParam;
        };
    }
}
}

#endif //VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_SDMPPROCESSOR_H
