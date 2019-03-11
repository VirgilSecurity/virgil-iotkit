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

#include <virgil/soraa/registrator/Filesystem.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <fstream>
#include <iostream>
#include <exception>
#include <iterator>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

using virgil::soraa::registrator::Filesystem;
using virgil::crypto::VirgilByteArrayUtils;

std::string Filesystem::currentPath_;

const size_t Filesystem::kFileSizeLimit = 10240;
const std::string Filesystem::kBackupFileSuffix = ".bak";

VirgilByteArray Filesystem::loadFile(const std::string & filename, const std::string & basePath) {
    VirgilByteArray res;
    try {
        // open the file
        std::string fixedFilename;
        
        if (filename.empty()) {
            throw std::runtime_error("File name is empty.");
        }
        
        fixedFilename = fixPath(filename, basePath);
        
        std::ifstream file(fixedFilename, std::ios::binary);
    
        // Stop eating new lines in binary mode !!!
        file.unsetf(std::ios::skipws);
    
        // get its size
        std::streampos fileSize;
    
        file.seekg(0, std::ios::end);
        fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        if (fileSize > kFileSizeLimit) {
            throw std::runtime_error(std::string("File size more than ") + std::to_string(kFileSizeLimit) + " bytes.");
        }
    
        // reserve capacity
        res.reserve(fileSize);
    
        // read the data
        res.insert(res.begin(),
               std::istream_iterator<uint8_t>(file),
               std::istream_iterator<uint8_t>());
    } catch (std::runtime_error & e) {
        std::cerr << "ERROR: can't load " << filename << ". " << e.what() << std::endl;
        throw e;
    }
    
    return res;
}

std::string Filesystem::loadTextFile(const std::string & filename, const std::string & basePath) {
    return VirgilByteArrayUtils::bytesToString(loadFile(filename, basePath));
}

std::string Filesystem::home() {
    struct passwd *pw = getpwuid(getuid());
    const char *homedir = pw->pw_dir;
    if (homedir) {
        return std::string(homedir);
    }
    return "";
}

std::string Filesystem::fixHomePath(const std::string & path) {
    if (path.empty() || path.front() == '/') {
        return path;
    }
    
    if (path.empty() || path.front() == '~') {
        return home() + path.substr(1);
    }
    
    return path;
}

std::string Filesystem::fixPath(const std::string & path, const std::string & basePath) {
    
    if (path.empty()) return path;
    
    std::string res;
    
    if (path.front() == '.') {
        if (basePath.empty()) {
            res += currentPath_;
        } else {
            res += basePath;
        }
        res += std::string("/") + path;
    } else {
        if (basePath.empty()) {
            res = fixHomePath(path);
        } else {
            res = basePath + "/" + path;
        }
    }
    
    return res;
}

std::string Filesystem::filePath(const std::string & filename) {
    if (filename.empty()) return "";
    const auto filenameFixed = Filesystem::fixPath(filename);
    return filenameFixed.substr(0, filenameFixed.find_last_of("/"));
}

void Filesystem::init() {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd))) {
        currentPath_ = std::string(cwd);
    }
}

bool Filesystem::fileExists(const std::string & filename, const std::string & basePath) {
    struct stat buffer;
    return (stat (fixPath(filename, basePath).c_str(), &buffer) == 0);
}

bool Filesystem::appendToTextFile(const std::string & data, const std::string & filename, const std::string & basePath) {
    std::ofstream output;
    output.open(fixPath(filename, basePath), std::ios_base::app);
    
    output << data;
    output.flush();
    
    return true;
}

bool Filesystem::createBackupFile(const std::string & filename, const std::string & basePath) {
    
    const auto fixedFileName = fixPath(filename, basePath);
    const auto backupFile = fixedFileName + kBackupFileSuffix;
    
    if (fileExists(backupFile)) {
        remove(backupFile.c_str());
    }
    
    try {
        // Copy file to backup file
        std::ifstream _src(fixedFileName, std::ios::binary);
        std::ofstream _dst(backupFile, std::ios::binary);
        
        std::istreambuf_iterator<char> beginSrc(_src);
        std::istreambuf_iterator<char> endSrc;
        std::ostreambuf_iterator<char> beginDst(_dst);
        std::copy(beginSrc, endSrc, beginDst);
        
        _src.close();
        _dst.close();
    } catch (const std::runtime_error & e) {
        std::cout << "Can't create backup file for " << fixedFileName << std::endl;
    }
    
    return true;
}
