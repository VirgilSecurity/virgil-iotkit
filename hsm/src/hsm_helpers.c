//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#include <string.h>
#include <stdlib-config.h>
#include <virgil/iot/hsm/hsm_interface.h>

/******************************************************************************/
int
vs_hsm_get_pubkey_len(vs_hsm_keypair_type_e keypair_type) {
    switch (keypair_type) {
#if USE_RSA
    case VS_KEYPAIR_RSA_2048:
        return 256;
#endif
    case VS_KEYPAIR_EC_SECP192R1:
    case VS_KEYPAIR_EC_SECP192K1:
        return 49;
    case VS_KEYPAIR_EC_SECP224R1:
    case VS_KEYPAIR_EC_SECP224K1:
        return 57;
    case VS_KEYPAIR_EC_SECP256R1:
    case VS_KEYPAIR_EC_SECP256K1:
        return 65;
    case VS_KEYPAIR_EC_SECP384R1:
        return 97;
    case VS_KEYPAIR_EC_SECP521R1:
        return 133;
    case VS_KEYPAIR_EC_CURVE25519:
    case VS_KEYPAIR_EC_ED25519:
        return 32;
    default:
        return -VS_HSM_ERR_INVAL;
    }
}

/******************************************************************************/
int
vs_hsm_get_signature_len(vs_hsm_keypair_type_e keypair_type) {
    switch (keypair_type) {
#if USE_RSA
    case VS_KEYPAIR_RSA_2048:
        return 256;
#endif
    case VS_KEYPAIR_EC_SECP192R1:
    case VS_KEYPAIR_EC_SECP192K1:
        return 48;
    case VS_KEYPAIR_EC_SECP224R1:
    case VS_KEYPAIR_EC_SECP224K1:
        return 56;
    case VS_KEYPAIR_EC_SECP256R1:
    case VS_KEYPAIR_EC_SECP256K1:
        return 64;
    case VS_KEYPAIR_EC_SECP384R1:
        return 96;
    case VS_KEYPAIR_EC_SECP521R1:
        return 132;
    case VS_KEYPAIR_EC_ED25519:
        return 64;
    default:
        return -VS_HSM_ERR_INVAL;
    }
}

/******************************************************************************/
int
vs_hsm_get_hash_len(vs_hsm_hash_type_e hash_type) {
    switch (hash_type) {
    case VS_HASH_SHA_256:
        return 32;
    case VS_HASH_SHA_384:
        return 48;
    case VS_HASH_SHA_512:
        return 64;
    default:
        return -1;
    }
}