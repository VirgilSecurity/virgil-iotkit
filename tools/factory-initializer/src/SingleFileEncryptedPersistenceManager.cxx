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

#include <virgil/iot/initializer/SingleFileEncryptedPersistenceManager.h>
#include <virgil/iot/initializer/Filesystem.h>
#include "virgil/sdk/crypto/Crypto.h"

using virgil::iot::initializer::SingleFileEncryptedPersistenceManager;
using virgil::iot::initializer::Filesystem;
using virgil::sdk::crypto::Crypto;

SingleFileEncryptedPersistenceManager::SingleFileEncryptedPersistenceManager(const std::string &filename,
                                                                             std::shared_ptr<Crypto> crypto,
                                                                             sdk::crypto::keys::PrivateKey privateKey,
                                                                             std::vector<sdk::crypto::keys::PublicKey> publicKeys)
: filename_(std::move(filename)), crypto_(std::move(crypto)), privateKey_(std::move(privateKey)), publicKeys_(std::move(publicKeys)) {
}

void SingleFileEncryptedPersistenceManager::persist(const std::string &data) {
    
    Filesystem::createBackupFile(filename_);

    auto encryptedData = crypto_->signThenEncrypt(VirgilByteArrayUtils::stringToBytes(data), privateKey_, publicKeys_);
    auto base64EncryptedData = VirgilBase64::encode(encryptedData);
    base64EncryptedData.push_back('\n');

    Filesystem::appendToTextFile(base64EncryptedData, filename_);
}
