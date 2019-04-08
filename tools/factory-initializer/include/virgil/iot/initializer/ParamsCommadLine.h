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

#ifndef VIRGIL_IOT_MANUFACTURE_PARAMSCOMMANDLINE_H
#define VIRGIL_IOT_MANUFACTURE_PARAMSCOMMANDLINE_H

#include <memory>

#include <virgil/iot/initializer/ParamsInterface.h>


namespace virgil {
namespace iot {
namespace initializer {
class ParamsCommadLine : public ParamsInterface {
public:
    ParamsCommadLine(int argc, char *argv[]);

    // Used for encryption of file with requests for Cards registration
    VirgilByteArray
    fileEncryptionPrivateKey() const final;
    std::string
    fileEncryptionPrivateKeyPassword() const final;
    VirgilByteArray
    fileRecipientPublicKey() const final;
    std::string
    exportFile() const final;
    std::string
    deviceInfoFile() const final;

    // Info for device provisioning
    ProvisioningInfo
    provisioningInfo() const final;

    // Credantials for signature of public key of device
    VirgilByteArray
    deviceSignPrivateKey() const final;
    std::string
    deviceSignPrivateKeyPassword() const final;
    std::string
    factoryPrivateKey() const final;

private:
    std::string exportFile_;
    std::string deviceInfoOutput_;

    VirgilByteArray fileEncryptionPrivateKey_;
    std::string fileEncryptionPrivateKeyPassword_;
    VirgilByteArray fileRecipientPublicKey_;

    ProvisioningInfo provisioningInfo_;

    VirgilByteArray deviceSignPrivateKey_;
    std::string deviceSignPrivateKeyPassword_;
    std::string factoryPrivateKey_;
};
} // namespace initializer
} // namespace iot
} // namespace virgil

#endif // VIRGIL_IOT_MANUFACTURE_PARAMSCOMMANDLINE_H
