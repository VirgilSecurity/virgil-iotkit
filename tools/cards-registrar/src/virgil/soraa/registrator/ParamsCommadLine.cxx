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

#include <virgil/iot/registrator/ParamsCommadLine.h>
#include <virgil/iot/registrator/Filesystem.h>
#include <externals/cxxopts.hpp>

using virgil::iot::registrator::ParamsCommadLine;
using virgil::iot::registrator::Filesystem;

ParamsCommadLine::ParamsCommadLine(int argc, char *argv[]) {
    
    try {
        std::string filePrivateKeyFile;
        std::string filePrivateKeyPassword;
        std::string fileSenderKey;
        
        std::string appID;
        std::string apiKeyID;
        std::string apiPrivateKeyFile;
        std::string iotPrivateKeyFile;
        std::string cardServiceBaseUrl;
        
        VirgilByteArray apiPrivateKey;
        VirgilByteArray iotPrivateKey;
        
        cxxopts::Options options(argv[0], " - Cards registrar for IoT devices");
        
        options.add_options()
        ("d,data", "File with encrypted data", cxxopts::value<std::string>(dataFile_))
        ("k,file_key", "File with private key to decrypt received data file", cxxopts::value<std::string>(filePrivateKeyFile))
        ("p,file_key_pass", "Password file with private key to decrypt received data file", cxxopts::value<std::string>(fileDecryptionPrivateKeyPassword_))
        ("s,file_sender_key", "Public key of sender of data file", cxxopts::value<std::string>(fileSenderKey))
        ("a,app_id", "Virgil Application ID", cxxopts::value<std::string>(appID))
        ("t,api_key_id", "Virgil Api key Id", cxxopts::value<std::string>(apiKeyID))
        ("y,api_key", "Virgil Api private key", cxxopts::value<std::string>(apiPrivateKeyFile))
        ("i,iot_priv_key", "Private key", cxxopts::value<std::string>(iotPrivateKeyFile))
        ("b,base_url", "Card service base url", cxxopts::value<std::string>(cardServiceBaseUrl));

        options.parse(argc, argv);

        if (options.count("help")) {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        if (dataFile_.empty()) {
            throw cxxopts::OptionException("Data file does't specified.");
        }

        if (!filePrivateKeyFile.empty()) {
            fileDecryptionPrivateKey_ = Filesystem::loadFile(filePrivateKeyFile);
        } else {
            throw cxxopts::OptionException("Private key for file decryption doesn't specified.");
        }
        
        if (!fileSenderKey.empty()) {
            fileSenderPublicKey_ = Filesystem::loadFile(fileSenderKey);
        } else {
            throw cxxopts::OptionException("File with public key of data sender doesn't specified.");
        }
        
        if (appID.empty()) {
            throw cxxopts::OptionException("Application ID does't specified.");
        }
        
        if (apiKeyID.empty()) {
            throw cxxopts::OptionException("Api key Id does't specified.");
        }

        if (cardServiceBaseUrl.empty()) {
            throw cxxopts::OptionException("Cerd service base url does't specified.");
        }

        if (!apiPrivateKeyFile.empty()) {
            apiPrivateKey = VirgilBase64::decode(Filesystem::loadTextFile(apiPrivateKeyFile));
        } else {
            throw cxxopts::OptionException("Api private key file doesn't specified.");
        }

        if (!iotPrivateKeyFile.empty()) {
            iotPrivateKey = VirgilBase64::decode(Filesystem::loadTextFile(iotPrivateKeyFile));
        } else {
            throw cxxopts::OptionException("Private key file for sign serial doesn't specified.");
        }

        cardsServiceInfo_ = CardsServiceInfo(appID,
                                             apiKeyID,
                                             apiPrivateKey,
                                             iotPrivateKey,
                                             cardServiceBaseUrl);
        
    } catch (const cxxopts::OptionException& e) {
        std::cerr << "error parsing options: " << e.what() << std::endl;
        exit(1);
    }
}

std::string ParamsCommadLine::dataFile() const {
    return dataFile_;
}

VirgilByteArray ParamsCommadLine::fileDecryptionPrivateKey() const {
    return fileDecryptionPrivateKey_;
}


std::string ParamsCommadLine::fileDecryptionPrivateKeyPassword() const {
    return fileDecryptionPrivateKeyPassword_;
}


VirgilByteArray ParamsCommadLine::fileSenderPublicKey() const {
    return fileSenderPublicKey_;
}

CardsServiceInfo ParamsCommadLine::cardsServiceInfo() const {
    return cardsServiceInfo_;
}
