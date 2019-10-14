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

#include <virgil/iot/vs-softhsm/vs-softhsm.h>
#include <virgil/iot/macros/macros.h>
#include "private/vs-softhsm-internal.h"

static vs_hsm_impl_t _softhsm;
static bool _softhsm_ready = false;

/******************************************************************************/
vs_hsm_impl_t*
vs_softhsm_impl(vs_storage_op_ctx_t *tl_storage_impl) {

    CHECK_NOT_ZERO_RET(tl_storage_impl, NULL);

    if (!_softhsm_ready) {
        _fill_slots_impl(&_softhsm, tl_storage_impl);
        _fill_crypto_impl(&_softhsm);
        _fill_keypair_impl(&_softhsm);
        _fill_ecies_impl(&_softhsm);
        _fill_soft_hash_impl(&_softhsm);

        _softhsm_ready = true;
    }
    return &_softhsm;
}

/******************************************************************************/
const vs_hsm_impl_t*
_softhsm_intern(void) {
    if (_softhsm_ready) {
        return &_softhsm;
    }

    return NULL;
}

/******************************************************************************/
const char *
get_slot_name(vs_iot_hsm_slot_e slot) {
    switch (slot) {
        case VS_KEY_SLOT_STD_OTP_0:
            return "STD_OTP_0";
        case VS_KEY_SLOT_STD_OTP_1:
            return "STD_OTP_1";
        case VS_KEY_SLOT_STD_OTP_2:
            return "STD_OTP_2";
        case VS_KEY_SLOT_STD_OTP_3:
            return "STD_OTP_3";
        case VS_KEY_SLOT_STD_OTP_4:
            return "STD_OTP_4";
        case VS_KEY_SLOT_STD_OTP_5:
            return "STD_OTP_5";
        case VS_KEY_SLOT_STD_OTP_6:
            return "STD_OTP_6";
        case VS_KEY_SLOT_STD_OTP_7:
            return "STD_OTP_7";
        case VS_KEY_SLOT_STD_OTP_8:
            return "STD_OTP_8";
        case VS_KEY_SLOT_STD_OTP_9:
            return "STD_OTP_9";
        case VS_KEY_SLOT_STD_OTP_10:
            return "STD_OTP_10";
        case VS_KEY_SLOT_STD_OTP_11:
            return "STD_OTP_11";
        case VS_KEY_SLOT_STD_OTP_12:
            return "STD_OTP_12";
        case VS_KEY_SLOT_STD_OTP_13:
            return "STD_OTP_13";
        case VS_KEY_SLOT_STD_OTP_14:
            return "STD_OTP_14";
        case VS_KEY_SLOT_EXT_OTP_0:
            return "EXT_OTP_0";
        case VS_KEY_SLOT_STD_MTP_0:
            return "STD_MTP_0";
        case VS_KEY_SLOT_STD_MTP_1:
            return "STD_MTP_1";
        case VS_KEY_SLOT_STD_MTP_2:
            return "STD_MTP_2";
        case VS_KEY_SLOT_STD_MTP_3:
            return "STD_MTP_3";
        case VS_KEY_SLOT_STD_MTP_4:
            return "STD_MTP_4";
        case VS_KEY_SLOT_STD_MTP_5:
            return "STD_MTP_5";
        case VS_KEY_SLOT_STD_MTP_6:
            return "STD_MTP_6";
        case VS_KEY_SLOT_STD_MTP_7:
            return "STD_MTP_7";
        case VS_KEY_SLOT_STD_MTP_8:
            return "STD_MTP_8";
        case VS_KEY_SLOT_STD_MTP_9:
            return "STD_MTP_9";
        case VS_KEY_SLOT_STD_MTP_10:
            return "STD_MTP_10";
        case VS_KEY_SLOT_STD_MTP_11:
            return "STD_MTP_11";
        case VS_KEY_SLOT_STD_MTP_12:
            return "STD_MTP_12";
        case VS_KEY_SLOT_STD_MTP_13:
            return "STD_MTP_13";
        case VS_KEY_SLOT_STD_MTP_14:
            return "STD_MTP_14";
        case VS_KEY_SLOT_EXT_MTP_0:
            return "EXT_MTP_0";
        case VS_KEY_SLOT_STD_TMP_0:
            return "STD_TMP_0";
        case VS_KEY_SLOT_STD_TMP_1:
            return "STD_TMP_1";
        case VS_KEY_SLOT_STD_TMP_2:
            return "STD_TMP_2";
        case VS_KEY_SLOT_STD_TMP_3:
            return "STD_TMP_3";
        case VS_KEY_SLOT_STD_TMP_4:
            return "STD_TMP_4";
        case VS_KEY_SLOT_STD_TMP_5:
            return "STD_TMP_5";
        case VS_KEY_SLOT_STD_TMP_6:
            return "STD_TMP_6";
        case VS_KEY_SLOT_EXT_TMP_0:
            return "EXT_TMP_0";

        default:
            assert(false && "Unsupported slot");
            return NULL;
    }
}
/******************************************************************************/