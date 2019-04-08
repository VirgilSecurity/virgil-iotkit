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

#ifndef VIRGIL_IOT_DEVICE_REGISTRATOR_SINGLEFILEENCRYPTEDREQUESTPROVIDER_H
#define VIRGIL_IOT_DEVICE_REGISTRATOR_SINGLEFILEENCRYPTEDREQUESTPROVIDER_H

#include <fstream>
#include <memory>
#include <list>

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/iot/registrator/Common.h>
#include <virgil/iot/registrator/RequestProviderInterface.h>

namespace virgil {
namespace iot {
namespace registrar {
class SingleFileEncryptedRequestProvider : public RequestProviderInterface {
public:
    SingleFileEncryptedRequestProvider(std::shared_ptr<virgil::sdk::crypto::Crypto> crypto,
                                       const sdk::crypto::keys::PrivateKey &privateKey,
                                       const sdk::crypto::keys::PublicKey &publicKey,
                                       const std::string &filename);

    std::string
    getData() override;
    std::string
    getSerialNumbers() override;
    bool
    hasData() const override;

private:
    std::list<std::string> cardRequests_;
    std::list<std::string> serialNumbers_;
};
} // namespace registrar
} // namespace iot
} // namespace virgil

#endif // VIRGIL_IOT_DEVICE_REGISTRATOR_SINGLEFILEENCRYPTEDREQUESTPROVIDER_H
