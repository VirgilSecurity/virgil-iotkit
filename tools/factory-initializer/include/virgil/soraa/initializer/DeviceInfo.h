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

#ifndef VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_DEVICEINFO_H
#define VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_DEVICEINFO_H

#include <string>
#include <unordered_map>

namespace virgil {
namespace soraa {
    namespace initializer {
        class DeviceInfo {
        public:
            DeviceInfo() = default;
            DeviceInfo(std::string identity, std::string identityType, std::string device, std::string deviceName,
                     std::unordered_map<std::string, std::string> payload);
            const std::string getAllDeviceInfo() const;

            const std::string &identity() const { return identity_; }
            const std::string &identityType() const { return identityType_; }
            const std::string &device() const { return device_; }
            const std::string &deviceName() const { return deviceName_; }
            const std::unordered_map<std::string, std::string> &payload() const { return payload_; }

        private:
            std::string identity_;
            std::string identityType_;
            std::string device_;
            std::string deviceName_;
            std::unordered_map<std::string, std::string> payload_;
        };
    }
}
}

#endif //VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_DEVICEINFO_H
