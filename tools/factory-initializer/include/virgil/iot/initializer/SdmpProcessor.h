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

using virgil::soraa::initializer::ProvisioningInfo;
using virgil::soraa::initializer::SignerInterface;

#define SIGNATURE_SZ      (64)
#define SALT_SZ           (32)
#define PUBKEY_TINY_SZ    (64)
#define PUBKEY_TINY_ID_SZ (2)
#define SERIAL_SIZE       (32)

namespace virgil {
namespace soraa {
    namespace initializer {
        typedef struct SOneDev {
            std::string macAddr;
            DeviceType type;
        } SOneDev_t;

        enum dev_type_t {
            dev_unknown = 0x00,
            dev_lamp,
            dev_snap,
            dev_gateway,
            dev_ncm,
        };

        typedef struct __attribute__((__packed__)) {
            uint8_t mac[6];
            dev_type_t deviceType;
            uint8_t reserved[10];
        } service_PRVS_DNID_t;

        typedef struct __attribute__((__packed__)) {
            uint8_t data_sz;
            uint8_t device_type;
            uint8_t data[200];
        } service_PRVS_data_t;

        typedef struct __attribute__((__packed__)) {
            uint8_t val[PUBKEY_TINY_ID_SZ];
        } crypto_public_key_id_t;

        typedef struct __attribute__((__packed__)) {
            crypto_public_key_id_t signer_id;
            uint8_t val[SIGNATURE_SZ];
        } crypto_signature_t;

        typedef struct __attribute__((__packed__)) {
            uint8_t tiny[PUBKEY_TINY_SZ];
            uint8_t full_sz;
            uint8_t full[100];
        } service_PRVS_own_key_t;

        typedef struct __attribute__((__packed__)) {
            uint32_t manufacturer;
            uint32_t model;
            uint8_t mac[6];
            uint8_t udid_of_device[32];
            crypto_signature_t signature;
            service_PRVS_own_key_t own_key;
        } service_PRVS_provision_info_t;

        typedef struct __attribute__((__packed__)) {
            uint16_t id;
            uint8_t val_sz;
            uint8_t val[];
        } service_PRVS_full_signature_t;

        typedef struct __attribute__((__packed__)) {
            service_PRVS_provision_info_t info;
            service_PRVS_full_signature_t signature;
        } service_PRVS_provision_info_signed_t;

        typedef struct __attribute__((__packed__)) {
            service_PRVS_own_key_t key;
            service_PRVS_full_signature_t signature;
        } service_PRVS_own_key_signed_t;
        
        class SdmpProcessor {
        public:
            SdmpProcessor(const ProvisioningInfo & provisioningInfo,
                          std::string addr,
                          DeviceType type,
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

            static std::vector<SOneDev_t> discoverDevices();
            
        private:
            std::string createRequest(const std::string & action,
                                      const std::string & param,
                                      const std::string & value = "") const;

            static bool isOk(const std::string & netResponse);
            bool initDevice();
            bool setTrustList(const ProvisioningInfo & provisioningInfo) const;
            bool setKeys(const ProvisioningInfo & provisioningInfo) const;

            bool signDevice() const;
            bool getProvisionInfo();

            std::string addr_;
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
