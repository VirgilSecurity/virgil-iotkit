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

#include <virgil/iot/registrator/SingleFileEncryptedRequestProvider.h>
#include <algorithm>
#include <iostream>
#include <iterator>

using virgil::sdk::crypto::Crypto;
using virgil::iot::registrar::SingleFileEncryptedRequestProvider;
using namespace virgil::crypto;

SingleFileEncryptedRequestProvider::SingleFileEncryptedRequestProvider(
        std::shared_ptr<Crypto> crypto, const sdk::crypto::keys::PrivateKey &privateKey,
        const sdk::crypto::keys::PublicKey &publicKey,  const std::string &filename) {

        std::cout << "Txt input file mode" << std::endl;
        std::ifstream input;
        input.open(filename, std::fstream::in);

        std::transform(std::istream_iterator<std::string>(input),
                       std::istream_iterator<std::string>(),
                       std::back_inserter(cardRequests_),
                       [&] (const std::string & line) {
                           auto data = VirgilBase64::decode(line);
                           auto decryptedData = crypto->decryptThenVerify(data,
                                                                          privateKey,
                                                                          publicKey);
                           return bytes2str(decryptedData);
                       });
}

std::string SingleFileEncryptedRequestProvider::getData() {
    const auto res = cardRequests_.front();
    cardRequests_.pop_front();
    
    std::cout << "Input: " << res << std::endl;
    
    return res;
}

std::string SingleFileEncryptedRequestProvider::getSerialNumbers() {
    const auto res = serialNumbers_.front();
    serialNumbers_.pop_front();

    std::cout << "Input: " << res << std::endl;

    return res;
}

bool SingleFileEncryptedRequestProvider::hasData() const {
    return !cardRequests_.empty() ;
}
