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

#ifndef VIRGIL_IOT_MANUFACTURE_SDMPCRYPTOSIGNER_H
#define VIRGIL_IOT_MANUFACTURE_SDMPCRYPTOSIGNER_H

#include <memory>

#include <virgil/iot/initializer/SignerInterface.h>
#include <virgil/iot/initializer/SdmpProcessor.h>
#include <virgil/sdk/crypto/keys/PrivateKey.h>

using virgil::iot::initializer::SdmpProcessor;

namespace virgil {
namespace iot {
namespace initializer {
class SdmpSigner : public SignerInterface {
public:
    SdmpSigner(std::shared_ptr<SdmpProcessor> processor);

    VirgilByteArray
    sign(const VirgilByteArray &data) override;
    bool
    verify(const VirgilByteArray &data, const VirgilByteArray &signature, const VirgilByteArray &publicKey) override;
    uint16_t
    signerId() override;
    VirgilByteArray
    publicKeyFull() override;

private:
    std::shared_ptr<SdmpProcessor> processor_;
};
} // namespace initializer
} // namespace iot
} // namespace virgil

#endif // VIRGIL_IOT_MANUFACTURE_SDMPCRYPTOSIGNER_H
