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

static vs_storage_op_ctx_t *_storage = NULL;

/********************************************************************************/
static vs_status_e
vs_secmodule_slot_save(vs_iot_secmodule_slot_e slot, const uint8_t *data, uint16_t data_sz) {
    CHECK_NOT_ZERO_RET(_storage, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
static vs_status_e
vs_secmodule_slot_load(vs_iot_secmodule_slot_e slot, uint8_t *data, uint16_t buf_sz, uint16_t *out_sz) {
    CHECK_NOT_ZERO_RET(_storage, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
static vs_status_e
vs_secmodule_slot_delete(vs_iot_secmodule_slot_e slot) {
    CHECK_NOT_ZERO_RET(_storage, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
void
_secmodule_deinit(void) {
    if (_storage && _storage->impl_func.deinit) {
        _storage->impl_func.deinit(_storage->impl_data);
    }
}

/******************************************************************************/
vs_status_e
_fill_slots_impl(vs_secmodule_impl_t *secmodule_impl, vs_storage_op_ctx_t *slots_storage_impl) {
    CHECK_NOT_ZERO_RET(secmodule_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(slots_storage_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);

    _storage = slots_storage_impl;

    secmodule_impl->deinit = _secmodule_deinit;

    secmodule_impl->slot_load = vs_secmodule_slot_load;
    secmodule_impl->slot_save = vs_secmodule_slot_save;
    secmodule_impl->slot_clean = vs_secmodule_slot_delete;

    return VS_CODE_OK;
}
