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

#ifndef VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_SDMPDEVICEINFOPROVIDER_H
#define VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_SDMPDEVICEINFOPROVIDER_H

#include <unordered_map>
#include <sstream>
#include <iomanip>

#include <virgil/soraa/initializer/DeviceInfoProviderInterface.h>
#include <virgil/soraa/initializer/SdmpProcessor.h>

using virgil::soraa::initializer::SdmpProcessor;

namespace virgil {
namespace soraa {
    namespace initializer {
        class SdmpDeviceInfoProvider: public DeviceInfoProviderInterface {
        public:
            SdmpDeviceInfoProvider(const ProvisioningInfo & provisioningInfo,
                                   std::shared_ptr<SdmpProcessor> processor);
            
            virtual DeviceInfo deviceInfo() final;
            virtual std::string payloadJson() final;

        private:
            std::unordered_map<std::string, std::string> payload();
            ProvisioningInfo provisioningInfo_;
            DeviceType deviceType_;
            std::shared_ptr<SdmpProcessor> processor_;
            
            static const std::string kIdentityType;
            static const std::string kDeviceTypeLamp;
            static const std::string kDeviceTypeSnap;
            static const std::string kDeviceTypeGateway;
            static const std::string kDeviceTypeNCM;
            static const std::string kDeviceTypeUnknown;

            template< typename T >
            std::string _hex(T i)
            {
                std::stringbuf buf;
                std::ostream os(&buf);

                os << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2)
                   << std::hex << i;

                return buf.str().c_str();
            }
        };
    }
}
}

#endif //VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_SDMPDEVICEINFOPROVIDER_H
