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
#include <stdbool.h>

#include <stdlib-config.h>
#include <logger-config.h>

#include <virgil/iot/provision/provision.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>

#include <virgil/iot/logger/logger.h>

static const size_t rec_key_slot[PROVISION_KEYS_QTY] = {REC1_KEY_SLOT, REC2_KEY_SLOT};

static const size_t auth_key_slot[PROVISION_KEYS_QTY] = {AUTH1_KEY_SLOT, AUTH2_KEY_SLOT};

static const size_t tl_key_slot[PROVISION_KEYS_QTY] = {TL1_KEY_SLOT, TL2_KEY_SLOT};

static const size_t fw_key_slot[PROVISION_KEYS_QTY] = {FW1_KEY_SLOT, FW2_KEY_SLOT};

/******************************************************************************/
static bool
_get_slot_num(vs_key_type_e key_type, uint8_t index, vs_iot_hsm_slot_e *slot) {
    bool res = true;

    const size_t *ptr;

    switch (key_type) {
    case VS_KEY_RECOVERY:
        ptr = rec_key_slot;
        break;
    case VS_KEY_AUTH:
        ptr = auth_key_slot;
        break;
    case VS_KEY_TRUSTLIST:
        ptr = tl_key_slot;
        break;
    case VS_KEY_FIRMWARE:
        ptr = fw_key_slot;
        break;
    default:
        return false;
    }

    *slot = ptr[index];

    return res;
}

/******************************************************************************/
bool
vs_provision_search_hl_pubkey(vs_key_type_e key_type, vs_hsm_keypair_type_e ec_type, uint8_t *key, uint16_t key_sz) {
    vs_iot_hsm_slot_e slot;
    uint8_t i = 0;
    int ref_key_sz;
    uint8_t buf[512];
    vs_pubkey_dated_t *ref_key = (vs_pubkey_dated_t *)buf;
    uint16_t _sz;

    for (i = 0; i < PROVISION_KEYS_QTY; ++i) {

        if (!_get_slot_num(key_type, i, &slot) || VS_HSM_ERR_OK != vs_hsm_slot_load(slot, buf, sizeof(buf), &_sz)) {
            return false;
        }

        ref_key_sz = vs_hsm_get_pubkey_len(ref_key->pubkey.ec_type);

        if (ref_key_sz < 0) {
            return false;
        }

        if (ref_key->pubkey.key_type == key_type && ref_key->pubkey.ec_type == ec_type && ref_key_sz == key_sz &&
            0 == memcmp(key, ref_key->pubkey.pubkey, key_sz)) {
            return true;
        }
    }

    return false;
}