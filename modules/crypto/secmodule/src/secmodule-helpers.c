//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
#include <stdbool.h>
#include <stdlib-config.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>

/******************************************************************************/
int
vs_secmodule_get_pubkey_len(vs_secmodule_keypair_type_e keypair_type) {
    switch (keypair_type) {
    case VS_KEYPAIR_EC_SECP192R1:
    case VS_KEYPAIR_EC_SECP192K1:
        return VS_PUBKEY_SECP192_LEN;
    case VS_KEYPAIR_EC_SECP224R1:
    case VS_KEYPAIR_EC_SECP224K1:
        return VS_PUBKEY_SECP224_LEN;
    case VS_KEYPAIR_EC_SECP256R1:
    case VS_KEYPAIR_EC_SECP256K1:
        return VS_PUBKEY_SECP256_LEN;
    case VS_KEYPAIR_EC_SECP384R1:
        return VS_PUBKEY_SECP384_LEN;
    case VS_KEYPAIR_EC_SECP521R1:
        return VS_PUBKEY_SECP521_LEN;
    case VS_KEYPAIR_EC_CURVE25519:
    case VS_KEYPAIR_EC_ED25519:
        return VS_PUBKEY_25519_LEN;
    default:
        VS_LOG_WARNING("Unsupported keypair type");
        return VS_CODE_ERR_CRYPTO;
    }
}

/******************************************************************************/
int
vs_secmodule_get_signature_len(vs_secmodule_keypair_type_e keypair_type) {
    switch (keypair_type) {
    case VS_KEYPAIR_EC_SECP192R1:
    case VS_KEYPAIR_EC_SECP192K1:
        return VS_SIGNATURE_SECP192_LEN;
    case VS_KEYPAIR_EC_SECP224R1:
    case VS_KEYPAIR_EC_SECP224K1:
        return VS_SIGNATURE_SECP224_LEN;
    case VS_KEYPAIR_EC_SECP256R1:
    case VS_KEYPAIR_EC_SECP256K1:
        return VS_SIGNATURE_SECP256_LEN;
    case VS_KEYPAIR_EC_SECP384R1:
        return VS_SIGNATURE_SECP384_LEN;
    case VS_KEYPAIR_EC_SECP521R1:
        return VS_SIGNATURE_SECP521_LEN;
    case VS_KEYPAIR_EC_ED25519:
        return VS_SIGNATURE_25519_LEN;
    default:
        VS_LOG_WARNING("Unsupported signature type");
        return VS_CODE_ERR_CRYPTO;
    }
}

/******************************************************************************/
int
vs_secmodule_get_hash_len(vs_secmodule_hash_type_e hash_type) {
    switch (hash_type) {
    case VS_HASH_SHA_256:
        return VS_HASH_SHA256_LEN;
    case VS_HASH_SHA_384:
        return VS_HASH_SHA384_LEN;
    case VS_HASH_SHA_512:
        return VS_HASH_SHA512_LEN;
    default:
        VS_LOG_WARNING("Unsupported hash type");
        return VS_CODE_ERR_CRYPTO;
    }
}

/******************************************************************************/
const char *
vs_secmodule_keypair_type_descr(vs_secmodule_keypair_type_e type) {
    switch (type) {
    case VS_KEYPAIR_EC_SECP192R1:
        return "192-bits NIST";
    case VS_KEYPAIR_EC_SECP224R1:
        return "224-bits NIST";
    case VS_KEYPAIR_EC_SECP256R1:
        return "256-bits NIST";
    case VS_KEYPAIR_EC_SECP384R1:
        return "384-bits NIST";
    case VS_KEYPAIR_EC_SECP521R1:
        return "521-bits NIST";
    case VS_KEYPAIR_EC_SECP192K1:
        return "192-bits \"Koblitz\"";
    case VS_KEYPAIR_EC_SECP224K1:
        return "224-bits \"Koblitz\"";
    case VS_KEYPAIR_EC_SECP256K1:
        return "256-bits \"Koblitz\"";
    case VS_KEYPAIR_EC_CURVE25519:
        return "Curve 25519";
    case VS_KEYPAIR_EC_ED25519:
        return "Ed 25519";
    default:
        VS_LOG_WARNING("Unsupported keypair type");
        return NULL;
    }
}

/******************************************************************************/
const char *
vs_secmodule_hash_type_descr(vs_secmodule_hash_type_e type) {
    switch (type) {
    case VS_HASH_SHA_256:
        return "SHA 256";
    case VS_HASH_SHA_384:
        return "SHA 384";
    case VS_HASH_SHA_512:
        return "SHA 512";
    default:
        VS_LOG_WARNING("Unsupported hash type");
        return NULL;
    }
}

/******************************************************************************/
