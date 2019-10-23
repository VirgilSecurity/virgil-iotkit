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

/** Get public key length
 *
 * \param[in] keypair_type Key pair type. Cannot be \ref VS_KEYPAIR_INVALID or \ref VS_KEYPAIR_MAX.
 *
 * \return Public key length
 */
int
vs_hsm_get_pubkey_len(vs_hsm_keypair_type_e keypair_type);

/** Get signature length
 *
 * \param[in] keypair_type Key pair type. Cannot be \ref VS_KEYPAIR_INVALID or \ref VS_KEYPAIR_MAX.
 *
 * \return Signature length
 */
int
vs_hsm_get_signature_len(vs_hsm_keypair_type_e keypair_type);

/** Get hash length
 *
 * \param[in] hash_type Hash type. Cannot be \ref VS_HASH_SHA_INVALID.
 *
 * \return Hash length
 */
int
vs_hsm_get_hash_len(vs_hsm_hash_type_e hash_type);

/** Get key pair type description
 *
 * \param[in] type Key pair type. Cannot be \ref VS_KEYPAIR_INVALID or \ref VS_KEYPAIR_MAX.
 *
 * \return Key pair description in static buffer
 */
const char *
vs_hsm_keypair_type_descr(vs_hsm_keypair_type_e type);

/** Get hash type description
 *
 * \param[in] hash_type Hash type. Cannot be \ref VS_HASH_SHA_INVALID.
 *
 * \return Hash type description in static buffer
 */
const char *
vs_hsm_hash_type_descr(vs_hsm_hash_type_e type);

#endif // VS_HSM_HELPERS_H_
