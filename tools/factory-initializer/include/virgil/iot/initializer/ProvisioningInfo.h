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

#ifndef VIRGIL_IOT_DEVICE_INITIALIZER_PROVISIONINGINFO_H
#define VIRGIL_IOT_DEVICE_INITIALIZER_PROVISIONINGINFO_H

#include <string>
#include <unordered_map>
#include "Common.h"

typedef struct {
    uint8_t bytes[32];
} serial_number_t;

using virgil::iot::initializer::VirgilByteArray;

namespace virgil {
namespace iot {
    namespace initializer {
        
        typedef struct __attribute__((__packed__)) {
            uint32_t tl_size;
            uint16_t version;
            uint16_t pub_keys_count;
            uint8_t reserved[24];
        } trust_list_header_t;

        typedef struct __attribute__((__packed__)) {
            uint16_t auth_key_id;
            uint8_t auth_sign[64];
            uint16_t tl_service_id;
            uint8_t tl_service_sign[64];
            uint8_t tl_type;
            uint8_t reserved[32];
        } trust_list_footer_t;

        typedef struct __attribute__((__packed__)) {
            uint16_t id;
            uint16_t type;
            uint8_t reserved[28];
        } trust_list_pub_key_meta_t;

        typedef struct __attribute__((__packed__)) {
            uint8_t val[64];
            trust_list_pub_key_meta_t meta;
        } trust_list_pub_key_t;


        
        class ProvisioningInfo {
        public:
            ProvisioningInfo() = default;

            ProvisioningInfo(const std::string & iniFile);

            ProvisioningInfo(bool tl_only,
                             bool card_only,
                             VirgilByteArray & authPubKey1,
                             VirgilByteArray & authPubKey2,
                             VirgilByteArray & recPubKey1,
                             VirgilByteArray & recPubKey2,
                             VirgilByteArray & tlPubKey1,
                             VirgilByteArray & tlPubKey2,
                             VirgilByteArray & fwPubKey1,
                             VirgilByteArray & fwPubKey2,
                             VirgilByteArray & trustList);

            VirgilByteArray authPubKey1() const;
            VirgilByteArray authPubKey2() const;
            VirgilByteArray recPubKey1() const;
            VirgilByteArray recPubKey2() const;
            VirgilByteArray tlPubKey1() const;
            VirgilByteArray tlPubKey2() const;
            VirgilByteArray fwPubKey1() const;
            VirgilByteArray fwPubKey2() const;
            VirgilByteArray tlHeader() const;
            VirgilByteArray tlFooter() const;
            VirgilByteArray tlChunk(uint16_t chunkNum) const;
            uint16_t tlChunksAmount() const;

            bool trustListOnly() const;
            bool createCardOnly() const;

        private:
            void init(VirgilByteArray & authPubKey1,
                      VirgilByteArray & authPubKey2,
                      VirgilByteArray & recPubKey1,
                      VirgilByteArray & recPubKey2,
                      VirgilByteArray & tlPubKey1,
                      VirgilByteArray & tlPubKey2,
                      VirgilByteArray & fwPubKey1,
                      VirgilByteArray & fwPubKey2,
                      VirgilByteArray & trustList);

            bool trustListOnly_;
            bool createCardOnly_;

            trust_list_header_t tlHeader_;
            trust_list_footer_t tlFooter_;
            std::vector<trust_list_pub_key_t> trustListChunks_;
            VirgilByteArray authPubKey1_;
            VirgilByteArray authPubKey2_;

            VirgilByteArray recPubKey1_;
            VirgilByteArray recPubKey2_;

            VirgilByteArray tlPubKey1_;
            VirgilByteArray tlPubKey2_;

            VirgilByteArray fwPubKey1_;
            VirgilByteArray fwPubKey2_;
        };
    }
}
}

#endif //VIRGIL_IOT_DEVICE_INITIALIZER_PROVISIONINGINFO_H
