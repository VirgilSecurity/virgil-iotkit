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

#ifndef VS_IOT_PROVISION_H
#define VS_IOT_PROVISION_H

#include <virgil/iot/hsm/hsm_structs.h>

typedef enum {
    VS_KEY_RECOVERY = 0,
    VS_KEY_AUTH,
    VS_KEY_TRUSTLIST,
    VS_KEY_FIRMWARE,
    VS_KEY_FACTORY,
    VS_KEY_IOT_DEVICE,
    VS_KEY_USER_DEVICE,
    VS_KEY_FIRMWARE_INTERNAL,
    VS_KEY_AUTH_INTERNAL
} vs_key_type_e;

typedef struct __attribute__((__packed__)) {
    uint8_t signer_type;       // vs_key_type_e
    uint8_t ec_type;           // vs_hsm_keypair_type_e
    uint8_t hash_type;         // vs_hsm_hash_type_e
    uint8_t raw_sign_pubkey[]; // An array with raw signature and public key, size of elements depends on @ec_type
} vs_sign_t;

typedef struct __attribute__((__packed__)) {
    uint8_t key_type; // vs_key_type_e
    uint8_t ec_type;  // vs_hsm_keypair_type_e
    uint8_t pubkey[]; // public key, size of element depends on @ec_type
} vs_pubkey_t;

typedef struct __attribute__((__packed__)) {
    uint32_t start_date;
    uint32_t expire_date;
    vs_pubkey_t pubkey;
} vs_pubkey_dated_t;

bool
vs_provision_search_hl_pubkey(vs_key_type_e key_type, vs_hsm_keypair_type_e ec_type, uint8_t *key, uint16_t key_sz);

#endif // VS_IOT_PROVISION_H