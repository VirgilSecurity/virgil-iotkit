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

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/iot/registrator/Common.h>
#include <virgil/iot/registrator/Filesystem.h>
#include <virgil/iot/registrator/ParamsCommadLine.h>
#include <virgil/iot/registrator/LampRegistrator.h>
#include <virgil/iot/registrator/SingleFileEncryptedRequestProvider.h>

using virgil::sdk::crypto::Crypto;
using virgil::soraa::registrator::VirgilBase64;
using virgil::soraa::registrator::Filesystem;
using virgil::soraa::registrator::ParamsCommadLine;
using virgil::soraa::registrator::LampRegistrator;
using virgil::soraa::registrator::SingleFileEncryptedRequestProvider;

int main (int argc, char *argv[]) {
    Filesystem::init();
    
    // Get parameters
    auto params = std::make_shared<ParamsCommadLine>(argc, argv);
    
    // initialize crypto
    auto crypto = std::make_shared<Crypto>();
    
    // import keys for decryption and verifying
    auto privateKey = crypto->importPrivateKey(params->fileDecryptionPrivateKey(), params->fileDecryptionPrivateKeyPassword());
    auto publicKey = crypto->importPublicKey(params->fileSenderPublicKey());
    
    auto fixedDataFile = Filesystem::fixPath(params->dataFile());
    
    auto requestProvider = std::make_shared<SingleFileEncryptedRequestProvider>(crypto, privateKey, publicKey, fixedDataFile, params->isXlsInputFile());
    LampRegistrator registrator(requestProvider, params->cardsServiceInfo(), params->isXlsInputFile());
    
    registrator.registerLamps();

    return 0;
}
