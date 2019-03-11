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

#include "virgil/soraa/initializer/AtmelCryptoSigner.h"
#include <virgil/crypto.h>
#include <virgil/crypto_tiny.h>
#include <virgil/converters/converters_tiny.h>
#include <virgil/soraa/initializer/Filesystem.h>
#include <virgil/soraa/initializer/Crc16.h>

using virgil::soraa::initializer::AtmelCryptoSigner;
using virgil::soraa::initializer::VirgilByteArray;

AtmelCryptoSigner::AtmelCryptoSigner() {
    crypto_init();
}

VirgilByteArray AtmelCryptoSigner::sign(const VirgilByteArray &data) {
    auto res = VirgilByteArray();

    uint8_t signature[256];
    size_t signature_sz;
    if (crypto_sign(0, 0,
                    data.data(), data.size(),
                    signature, sizeof(signature), &signature_sz)) {
        res = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(signature, signature_sz);
    }

    return res;
}

bool AtmelCryptoSigner::verify(const VirgilByteArray &data, const VirgilByteArray &signature, const VirgilByteArray &publicKey) {
    return crypto_verify(publicKey.data(), publicKey.size(),
                         signature.data(), signature.size(),
                         data.data(), data.size());
}

uint16_t AtmelCryptoSigner::signerId() {
    uint8_t * key;
    crypto_tiny_own_public_key(&key);
    return Crc16::calc(key, 64);
}

VirgilByteArray AtmelCryptoSigner::publicKeyFull() {
    uint8_t * ownKey;
    crypto_tiny_own_public_key(&ownKey);

    uint8_t ownKeyFull[128];
    size_t ownKeyFullSz = sizeof(ownKeyFull);
    tiny_pubkey_to_virgil(ownKey, ownKeyFull, &ownKeyFullSz);

    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(ownKeyFull, ownKeyFullSz);
}