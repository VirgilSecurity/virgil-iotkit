
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

#include <virgil/iot/initializer/ProvisioningInfo.h>
#include <virgil/iot/initializer/Filesystem.h>
#include <externals/ini.hpp>

using virgil::soraa::initializer::ProvisioningInfo;
using virgil::soraa::initializer::Filesystem;

ProvisioningInfo::ProvisioningInfo(bool tl_only,
                                   bool card_only,
                                   VirgilByteArray & authPubKey1,
                                   VirgilByteArray & authPubKey2,
                                   VirgilByteArray & recPubKey1,
                                   VirgilByteArray & recPubKey2,
                                   VirgilByteArray & tlPubKey1,
                                   VirgilByteArray & tlPubKey2,
                                   VirgilByteArray & fwPubKey1,
                                   VirgilByteArray & fwPubKey2,
                                   VirgilByteArray & trustList) {
    init(authPubKey1,
         authPubKey2,
         recPubKey1,
         recPubKey2,
         tlPubKey1,
         tlPubKey2,
         fwPubKey1,
         fwPubKey2,
         trustList);
    trustListOnly_ = tl_only;
    createCardOnly_ = card_only;
}

void ProvisioningInfo::init(VirgilByteArray & authPubKey1,
                            VirgilByteArray & authPubKey2,
                            VirgilByteArray & recPubKey1,
                            VirgilByteArray & recPubKey2,
                            VirgilByteArray & tlPubKey1,
                            VirgilByteArray & tlPubKey2,
                            VirgilByteArray & fwPubKey1,
                            VirgilByteArray & fwPubKey2,
                            VirgilByteArray & trustList) {
    uint32_t tl_size;
    uint8_t *tl_ptr;
    authPubKey1_ = authPubKey1;
    authPubKey2_ = authPubKey2;
    recPubKey1_ = recPubKey1;
    recPubKey2_ = recPubKey2;
    tlPubKey1_ = tlPubKey1;
    tlPubKey2_ = tlPubKey2;
    fwPubKey1_ = fwPubKey1;
    fwPubKey2_ = fwPubKey2;
    trustListChunks_.clear();

    try {
        if(trustList.size() < sizeof(trust_list_header_t) + sizeof(trust_list_footer_t)) {
            const auto what(std::string("Wrong data in trust list\n"));
            throw std::runtime_error(what);
        }

        memcpy(reinterpret_cast<uint8_t *>(&tlHeader_),trustList.data(),sizeof(trust_list_header_t));

        tl_size = tlHeader_.pub_keys_count * sizeof(trust_list_pub_key_t)
                  + sizeof(trust_list_header_t)
                  + sizeof(trust_list_footer_t);

        if(trustList.size() != tlHeader_.tl_size
                || trustList.size() != tl_size) {
            const auto what(std::string("Wrong data in trust list\n"));
            throw std::runtime_error(what);
        }

        tl_ptr = &trustList[sizeof(trust_list_header_t)];

        for(uint16_t i = 0; i < tlHeader_.pub_keys_count; i ++) {
            trustListChunks_.push_back(*reinterpret_cast<trust_list_pub_key_t *>(tl_ptr));
            tl_ptr += sizeof(trust_list_pub_key_t);
        }

        memcpy(reinterpret_cast<uint8_t *>(&tlFooter_),tl_ptr,sizeof(trust_list_footer_t));

    } catch(...) {
        const auto what(std::string("Wrong data in trust list \n"));
        throw std::runtime_error(what);
    }

}

VirgilByteArray ProvisioningInfo::authPubKey1() const {
    return authPubKey1_;
}

VirgilByteArray ProvisioningInfo::authPubKey2() const {
    return authPubKey2_;
}

VirgilByteArray ProvisioningInfo::recPubKey1() const {
    return recPubKey1_;
}

VirgilByteArray ProvisioningInfo::recPubKey2() const {
    return recPubKey2_;
}

VirgilByteArray ProvisioningInfo::tlPubKey1() const {
    return tlPubKey1_;
}

VirgilByteArray ProvisioningInfo::tlPubKey2() const {
    return tlPubKey2_;
}

VirgilByteArray ProvisioningInfo::fwPubKey1() const {
    return fwPubKey1_;
}

VirgilByteArray ProvisioningInfo::fwPubKey2() const {
    return fwPubKey2_;
}

VirgilByteArray ProvisioningInfo::tlHeader() const {
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(reinterpret_cast<const char*> (&tlHeader_), sizeof(trust_list_header_t));
}

VirgilByteArray ProvisioningInfo::tlFooter() const {
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(reinterpret_cast<const char*> (&tlFooter_), sizeof(trust_list_footer_t));
}

VirgilByteArray ProvisioningInfo::tlChunk(uint16_t chunkNum) const {
    if(chunkNum >= tlChunksAmount()) {
        const auto what(std::string("trust list chunk request error\n"));
        throw std::runtime_error(what);
    }
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(reinterpret_cast<const char*> (&trustListChunks_[chunkNum]),
                                              sizeof(trust_list_pub_key_t));
}

uint16_t ProvisioningInfo::tlChunksAmount() const{
    return tlHeader_.pub_keys_count;
}

bool ProvisioningInfo::trustListOnly() const {
    return trustListOnly_;
}

bool ProvisioningInfo::createCardOnly() const {
    return createCardOnly_;
}