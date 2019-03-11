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

#include <virgil/soraa/initializer/DeviceInfo.h>
#include <virgil/sdk/util/JsonUtils.h>

using virgil::soraa::initializer::DeviceInfo;
using virgil::sdk::util::JsonUtils;

DeviceInfo::DeviceInfo(std::string identity, std::string identityType, std::string device, std::string deviceName,
        std::unordered_map<std::string, std::string> payload)
    : identity_(std::move(identity)), identityType_(std::move(identityType)), device_(std::move(device)),
      deviceName_(std::move(deviceName)), payload_(std::move(payload)) {
}

const std::string DeviceInfo::getAllDeviceInfo() const {
    std::unordered_map<std::string, std::string> allInfo;
    allInfo["device"] = device_;
    allInfo["device_name"] = deviceName_;

    for (const auto it : payload_) {
        allInfo[it.first] = it.second;
    }

    return JsonUtils::unorderedMapToJson(allInfo).dump();
}