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

#ifndef VS_HSM_STRUCTURES_API_H
#define VS_HSM_STRUCTURES_API_H

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/hsm/devices/hsm_none.h>
#include <virgil/iot/hsm/devices/hsm_custom.h>
#include <virgil/iot/hsm/devices/hsm_atecc_508a.h>
#include <virgil/iot/hsm/devices/hsm_atecc_608a.h>
#include <virgil/iot/hsm/devices/hsm_iotelic.h>

typedef enum {
    VS_KEYPAIR_INVALID = -1,
    VS_KEYPAIR_EC_SECP_MIN = 1,
    VS_KEYPAIR_EC_SECP192R1 = VS_KEYPAIR_EC_SECP_MIN, ///< 192-bits NIST curve
    VS_KEYPAIR_EC_SECP224R1,                          ///< 224-bits NIST curve
    VS_KEYPAIR_EC_SECP256R1,                          ///< 256-bits NIST curve
    VS_KEYPAIR_EC_SECP384R1,                          ///< 384-bits NIST curve
    VS_KEYPAIR_EC_SECP521R1,                          ///< 521-bits NIST curve
    VS_KEYPAIR_EC_SECP192K1,                          ///< 192-bits "Koblitz" curve
    VS_KEYPAIR_EC_SECP224K1,                          ///< 224-bits "Koblitz" curve
    VS_KEYPAIR_EC_SECP256K1,                          ///< 256-bits "Koblitz" curve
    VS_KEYPAIR_EC_SECP_MAX = VS_KEYPAIR_EC_SECP256K1,
    VS_KEYPAIR_EC_CURVE25519, ///< Curve25519
    VS_KEYPAIR_EC_ED25519,    ///< Ed25519
    VS_KEYPAIR_RSA_2048,      ///< RSA 2048 bit (not recommended)
    VS_KEYPAIR_MAX
} vs_hsm_keypair_type_e;

typedef enum {
    VS_HASH_SHA_INVALID = -1,
    VS_HASH_SHA_256 = 0,
    VS_HASH_SHA_384,
    VS_HASH_SHA_512,
} vs_hsm_hash_type_e;

typedef enum {
    VS_KDF_INVALID = -1,
    VS_KDF_2 = 0,
} vs_hsm_kdf_type_e;

typedef enum { VS_AES_GCM } vs_iot_aes_type_e;

#endif // VS_HSM_STRUCTURES_API_H