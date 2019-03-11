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

#include <virgil/soraa/initializer/ParamsCommadLine.h>
#include <virgil/soraa/initializer/Filesystem.h>
#include <externals/cxxopts.hpp>

using virgil::soraa::initializer::ParamsCommadLine;
using virgil::soraa::initializer::Filesystem;

ParamsCommadLine::ParamsCommadLine(int argc, char *argv[]) {
    
    try {
        std::string filePrivateKeyFile;
        std::string filePrivateKeyPassword;
        std::string fileRecipientKey;
        std::string fileAuthKey1;
        std::string fileAuthKey2;
        std::string fileRecoveryKey1;
        std::string fileRecoveryKey2;
        std::string fileTrustListKey1;
        std::string fileTrustListKey2;
        std::string fileFirmwareKey1;
        std::string fileFirmwareKey2;
        std::string fileTrustList;

        VirgilByteArray authPubKey1;
        VirgilByteArray authPubKey2;

        VirgilByteArray recPubKey1;
        VirgilByteArray recPubKey2;

        VirgilByteArray tlPubKey1;
        VirgilByteArray tlPubKey2;

        VirgilByteArray fwPubKey1;
        VirgilByteArray fwPubKey2;

        VirgilByteArray trustList;

        bool trustListOnly = false;
        bool createCardOnly = false;

        cxxopts::Options options(argv[0], " - Lamp Initializer command line options");
        
        options.add_options()
        ("o,output", "Encrypted output file", cxxopts::value<std::string>(exportFile_))
        ("i,device_info_output", "Device info output file", cxxopts::value<std::string>(deviceInfoOutput_))
        ("t,file_transfer_key", "File with private key for secure file transfer", cxxopts::value<std::string>(filePrivateKeyFile))
        ("a,file_transfer_key_pass", "Password for private key for secure file transfer", cxxopts::value<std::string>(filePrivateKeyPassword))
        ("r,file_recipient_key", "Public key for recipient of exported data file", cxxopts::value<std::string>(fileRecipientKey))
        ("u,auth_pub_key_1", "File with 1st auth public key", cxxopts::value<std::string>(fileAuthKey1))
        ("v,auth_pub_key_2", "File with 2nd auth public key", cxxopts::value<std::string>(fileAuthKey2))
        ("e,rec_pub_key_1", "File with 1st recovery public key", cxxopts::value<std::string>(fileRecoveryKey1))
        ("c,rec_pub_key_2", "File with 2nd recovery public key", cxxopts::value<std::string>(fileRecoveryKey2))
        ("b,tl_pub_key_1", "File with 1st trust list public key", cxxopts::value<std::string>(fileTrustListKey1))
        ("k,tl_pub_key_2", "File with 2nd trust list public key", cxxopts::value<std::string>(fileTrustListKey2))
        ("w,fw_pub_key_1", "File with 1st firmware public key", cxxopts::value<std::string>(fileFirmwareKey1))
        ("x,fw_pub_key_2", "File with 2nd firmware public key", cxxopts::value<std::string>(fileFirmwareKey2))
        ("f,trust_list", "File with trust list", cxxopts::value<std::string>(fileTrustList))
        ("d,create_card_only", "Create card request only", cxxopts::value<bool>(createCardOnly))
        ("y,trust_list_only", "Use Trust List only", cxxopts::value<bool>(trustListOnly))
        ("z,factory_key", "File with Factory private key", cxxopts::value<std::string>(factoryPrivateKey_));
        
        options.parse(argc, argv);
        
        if (options.count("help")) {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        if (factoryPrivateKey_.empty()) {
            std::cout << std::string("Factory private key doesn't set.") << std::endl;
            std::cout << std::string("!! Use Atmel Signer !!!") << std::endl;
        }

        if (fileRecipientKey.empty()) {
            throw cxxopts::OptionException("Public key for recipient of exported data file doesn't set.");
        }
        fileRecipientPublicKey_ = Filesystem::loadFile(fileRecipientKey);

        if (filePrivateKeyFile.empty()) {
            throw cxxopts::OptionException("Private file for secure file transfer doesn't set.");
        }
        fileEncryptionPrivateKeyPassword_ = filePrivateKeyPassword;
        fileEncryptionPrivateKey_ = Filesystem::loadFile(filePrivateKeyFile);

        if (fileAuthKey1.empty()) {
            throw cxxopts::OptionException("File with 1st auth public key doesn't set.");
        }
        authPubKey1 = Filesystem::loadFile(fileAuthKey1);

        if (fileAuthKey2.empty()) {
            throw cxxopts::OptionException("File with 2nd auth public key doesn't set.");
        }
        authPubKey2 = Filesystem::loadFile(fileAuthKey2);


        if (fileRecoveryKey1.empty()) {
            throw cxxopts::OptionException("File with 1st recovery public key doesn't set.");
        }
        recPubKey1 = Filesystem::loadFile(fileRecoveryKey1);

        if (fileRecoveryKey2.empty()) {
            throw cxxopts::OptionException("File with 2nd recovery public key doesn't set.");
        }
        recPubKey2 = Filesystem::loadFile(fileRecoveryKey2);


        if (fileTrustListKey1.empty()) {
            throw cxxopts::OptionException("File with 1st trust list public key doesn't set.");
        }
        tlPubKey1 = Filesystem::loadFile(fileTrustListKey1);

        if (fileTrustListKey2.empty()) {
            throw cxxopts::OptionException("File with 2nd trust list public key doesn't set.");
        }
        tlPubKey2 = Filesystem::loadFile(fileTrustListKey2);

        if (fileFirmwareKey1.empty()) {
            throw cxxopts::OptionException("File with 1st firmware public key doesn't set.");
        }
        fwPubKey1 = Filesystem::loadFile(fileFirmwareKey1);

        if (fileFirmwareKey2.empty()) {
            throw cxxopts::OptionException("File with 2nd firmware public key doesn't set.");
        }
        fwPubKey2 = Filesystem::loadFile(fileFirmwareKey2);

        if (fileTrustList.empty()) {
            throw cxxopts::OptionException("File with trust list doesn't set.");
        }

        trustList = Filesystem::loadFile(fileTrustList);

        provisioningInfo_ = ProvisioningInfo(trustListOnly,
                                             createCardOnly,
                                             authPubKey1,
                                             authPubKey2,
                                             recPubKey1,
                                             recPubKey2,
                                             tlPubKey1,
                                             tlPubKey2,
                                             fwPubKey1,
                                             fwPubKey2,
                                             trustList);

        if (options.count("output")) {
            exportFile_ = options["output"].as<std::string>();
        } else {
            throw cxxopts::OptionException("Output file does't specified.");
        }

        if (options.count("device_info_output")) {
            deviceInfoOutput_ = options["device_info_output"].as<std::string>();
        } else {
            throw cxxopts::OptionException("Device info output file does't specified.");
        }
        
    } catch (const cxxopts::OptionException& e) {
        std::cerr << "error parsing options: " << e.what() << std::endl;
        exit(1);
    }
}

std::string ParamsCommadLine::exportFile() const {
    return exportFile_;
}

std::string ParamsCommadLine::deviceInfoFile() const {
    return deviceInfoOutput_;
}

VirgilByteArray ParamsCommadLine::fileEncryptionPrivateKey() const {
    return fileEncryptionPrivateKey_;
}

std::string ParamsCommadLine::fileEncryptionPrivateKeyPassword() const {
    return fileEncryptionPrivateKeyPassword_;
}

VirgilByteArray ParamsCommadLine::fileRecipientPublicKey() const {
    return fileRecipientPublicKey_;
}

VirgilByteArray ParamsCommadLine::deviceSignPrivateKey() const {
    return deviceSignPrivateKey_;
}

std::string ParamsCommadLine::deviceSignPrivateKeyPassword() const {
    return deviceSignPrivateKeyPassword_;
}

ProvisioningInfo ParamsCommadLine::provisioningInfo() const {
    return provisioningInfo_;
}

std::string ParamsCommadLine::factoryPrivateKey() const {
    return factoryPrivateKey_;
}

