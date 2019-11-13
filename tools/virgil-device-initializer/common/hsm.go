//   Copyright (C) 2015-2019 Virgil Security Inc.
//
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//       (1) Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//       (2) Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//
//       (3) Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//   POSSIBILITY OF SUCH DAMAGE.
//
//   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


package common

import (
    "log"

    "gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

// vs_hsm_hash_type_e
const (
    VS_HASH_SHA_256 = iota
    VS_HASH_SHA_384
    VS_HASH_SHA_512
)

// vs_hsm_keypair_type_e
const (
    VS_KEYPAIR_EC_SECP192R1 = iota + 1
    VS_KEYPAIR_EC_SECP224R1
    VS_KEYPAIR_EC_SECP256R1
    VS_KEYPAIR_EC_SECP384R1
    VS_KEYPAIR_EC_SECP521R1
    VS_KEYPAIR_EC_SECP192K1
    VS_KEYPAIR_EC_SECP224K1
    VS_KEYPAIR_EC_SECP256K1
    VS_KEYPAIR_EC_CURVE25519
    VS_KEYPAIR_EC_ED25519
    VS_KEYPAIR_RSA_2048
)

func HsmHashTypeToVirgil(hashType int) virgil_crypto_go.VirgilCryptoFoundationVirgilHashAlgorithm {
    switch hashType {
    case VS_HASH_SHA_256:
        return virgil_crypto_go.VirgilHashAlgorithm_SHA256
    case VS_HASH_SHA_384:
        return virgil_crypto_go.VirgilHashAlgorithm_SHA384
    case VS_HASH_SHA_512:
        return virgil_crypto_go.VirgilHashAlgorithm_SHA512
    default:
        return -1
    }
}

func GetPublicKeySizeByECType(ECType uint8) int {
    size := 0

    switch ECType {
    case VS_KEYPAIR_EC_SECP192R1:
    case VS_KEYPAIR_EC_SECP192K1:
        size = 49
    case VS_KEYPAIR_EC_SECP224R1:
    case VS_KEYPAIR_EC_SECP224K1:
        size = 57
    case VS_KEYPAIR_EC_SECP256K1:
    case VS_KEYPAIR_EC_SECP256R1:
        size = 65
    case VS_KEYPAIR_EC_SECP384R1:
        size = 97
    case VS_KEYPAIR_EC_SECP521R1:
        size = 133
    case VS_KEYPAIR_EC_CURVE25519:
    case VS_KEYPAIR_EC_ED25519:
        size = 32
    default:
        log.Fatalf("GetPublicKeySizeByECType: Unknown ECType: %d", ECType)
    }
    return size
}

func GetSignatureSizeByECType(ECType uint8) int {
    size := 0

    switch ECType {
    case VS_KEYPAIR_RSA_2048:
        size = 256
    case VS_KEYPAIR_EC_SECP192R1:
    case VS_KEYPAIR_EC_SECP192K1:
        size = 48
    case VS_KEYPAIR_EC_SECP224R1:
    case VS_KEYPAIR_EC_SECP224K1:
        size = 56
    case VS_KEYPAIR_EC_SECP256K1:
    case VS_KEYPAIR_EC_SECP256R1:
        size = 64
    case VS_KEYPAIR_EC_SECP384R1:
        size = 96
    case VS_KEYPAIR_EC_SECP521R1:
        size = 132
    case VS_KEYPAIR_EC_ED25519:
        size = 64
    default:
        log.Fatalf("GetSignatureSizeByECType: Unknown ECType: %d", ECType)
    }
    return size
}
