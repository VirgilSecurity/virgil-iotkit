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

#include <virgil/iot/vs-ateccx08A-secmodule/vs-ateccx08A-secmodule.h>
#include <virgil/iot/macros/macros.h>
#include <private/vs-ateccx08A-secmodule-internal.h>

static vs_secmodule_impl_t _ateccx08_secmodule;
static bool _ateccx08_secmodule_ready = false;

/******************************************************************************/
vs_secmodule_impl_t *
vs_ateccx08A_secmodule_impl(vs_storage_op_ctx_t *slots_storage_impl) {

    CHECK_NOT_ZERO_RET(slots_storage_impl, NULL);

    if (!_ateccx08_secmodule_ready) {
        _fill_slots_impl(&_ateccx08_secmodule, slots_storage_impl);
        _fill_crypto_impl(&_ateccx08_secmodule);
        _fill_keypair_impl(&_ateccx08_secmodule);
        _fill_soft_hash_impl(&_ateccx08_secmodule);

        _ateccx08_secmodule_ready = true;
    }
    return &_ateccx08_secmodule;
}

/******************************************************************************/
const vs_secmodule_impl_t *
_ateccx08_secmodule_intern(void) {
    if (_ateccx08_secmodule_ready) {
        return &_ateccx08_secmodule;
    }

    return NULL;
}

/******************************************************************************/
vs_status_e
vs_ateccx08A_secmodule_deinit(void) {
    _ateccx08_secmodule_ready = false;
    _secmodule_deinit();

    return VS_CODE_OK;
}