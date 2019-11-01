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

/**
 * @file hsm_helpers.h
 * @brief HSM helper functions
 */

#ifndef VS_HSM_HELPERS_H_
#define VS_HSM_HELPERS_H_

#include <virgil/iot/hsm/hsm.h>

#define VS_PUBKEY_SECP192_LEN (49)
#define VS_PUBKEY_SECP224_LEN (57)
#define VS_PUBKEY_SECP256_LEN (65)
#define VS_PUBKEY_SECP384_LEN (97)
#define VS_PUBKEY_SECP521_LEN (133)
#define VS_PUBKEY_25519_LEN (32)

#if USE_RSA
#define VS_PUBKEY_RSA2048_LEN (256)
#endif

#define VS_SIGNATURE_SECP192_LEN (48)
#define VS_SIGNATURE_SECP224_LEN (56)
#define VS_SIGNATURE_SECP256_LEN (64)
#define VS_SIGNATURE_SECP384_LEN (96)
#define VS_SIGNATURE_SECP521_LEN (132)
#define VS_SIGNATURE_25519_LEN (64)

#if USE_RSA
#define VS_SIGNATURE_RSA2048_LEN (256)
#endif

#define VS_HASH_SHA256_LEN (32)
#define VS_HASH_SHA384_LEN (48)
#define VS_HASH_SHA512_LEN (64)


/** Get public key length
 *
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Public key length
 */
int
vs_hsm_get_pubkey_len(vs_hsm_keypair_type_e keypair_type);

/** Get signature length
 *
 * \param[in] keypair_type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Signature length
 */
int
vs_hsm_get_signature_len(vs_hsm_keypair_type_e keypair_type);

/** Get hash length
 *
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 *
 * \return Hash length
 */
int
vs_hsm_get_hash_len(vs_hsm_hash_type_e hash_type);

/** Get key pair type description
 *
 * \param[in] type Key pair type. Cannot be #VS_KEYPAIR_INVALID or #VS_KEYPAIR_MAX.
 *
 * \return Key pair description in static buffer
 */
const char *
vs_hsm_keypair_type_descr(vs_hsm_keypair_type_e type);

/** Get hash type description
 *
 * \param[in] hash_type Hash type. Cannot be #VS_HASH_SHA_INVALID.
 *
 * \return Hash type description in static buffer
 */
const char *
vs_hsm_hash_type_descr(vs_hsm_hash_type_e type);

#endif // VS_HSM_HELPERS_H_
