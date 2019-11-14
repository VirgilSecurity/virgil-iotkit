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

#include <virgil/iot/vs-soft-secmodule/vs-soft-secmodule.h>
#include <virgil/iot/macros/macros.h>
#include "private/vs-soft-secmodule-internal.h"

static vs_storage_op_ctx_t *_storage = NULL;

/********************************************************************************/
static vs_status_e
vs_hsm_slot_save(vs_iot_hsm_slot_e slot, const uint8_t *data, uint16_t data_sz) {
    CHECK_NOT_ZERO_RET(_storage, VS_CODE_ERR_NULLPTR_ARGUMENT);
    vs_storage_file_t f;
    vs_storage_element_id_t id;
    const char *slot_name = get_slot_name(slot);
    vs_status_e res;
    vs_status_e res_close = VS_CODE_OK;

    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    CHECK_RET(VS_IOT_STRLEN(slot_name) < sizeof(vs_storage_element_id_t),
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "Slot name too big");
    VS_IOT_STRCPY((char *)id, slot_name);

    CHECK(f = _storage->impl_func.open(_storage->impl_data, id), "Cannot open file");

    // Save data type to file
    STATUS_CHECK(res = _storage->impl_func.save(_storage->impl_data, f, 0, data, data_sz), "Can't save data to file");

    STATUS_CHECK(res = _storage->impl_func.sync(_storage->impl_data, f), "Can't sync secbox file");

terminate:

    if (f) {
        res_close = _storage->impl_func.close(_storage->impl_data, f);
    }

    return (VS_CODE_OK == res) ? res_close : res;
}

/********************************************************************************/
static vs_status_e
vs_hsm_slot_load(vs_iot_hsm_slot_e slot, uint8_t *data, uint16_t buf_sz, uint16_t *out_sz) {
    CHECK_NOT_ZERO_RET(_storage, VS_CODE_ERR_NULLPTR_ARGUMENT);
    vs_storage_file_t f;
    vs_storage_element_id_t id;
    const char *slot_name = get_slot_name(slot);
    vs_status_e res;
    vs_status_e res_close = VS_CODE_OK;
    ssize_t file_sz;

    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    CHECK_RET(VS_IOT_STRLEN(slot_name) < sizeof(vs_storage_element_id_t),
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "Slot name too big");
    VS_IOT_STRCPY((char *)id, slot_name);

    CHECK(f = _storage->impl_func.open(_storage->impl_data, id), "Cannot open file");

    // Get file size
    file_sz = _storage->impl_func.size(_storage->impl_data, id);
    CHECK(file_sz > 0, "Slot size is wrong");
    CHECK(file_sz <= buf_sz, "Cannot read file because of small buffer");

    // Load data type to file
    STATUS_CHECK(res = _storage->impl_func.load(_storage->impl_data, f, 0, data, file_sz), "Can't save data to file");

    *out_sz = file_sz;

terminate:

    if (f) {
        res_close = _storage->impl_func.close(_storage->impl_data, f);
    }

    return (VS_CODE_OK == res) ? res_close : res;
}

/******************************************************************************/
static vs_status_e
vs_hsm_slot_delete(vs_iot_hsm_slot_e slot) {
    vs_storage_element_id_t id;
    const char *slot_name = get_slot_name(slot);

    CHECK_NOT_ZERO_RET(_storage, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    CHECK_RET(VS_IOT_STRLEN(slot_name) < sizeof(vs_storage_element_id_t),
              VS_CODE_ERR_TOO_SMALL_BUFFER,
              "Slot name too big");
    VS_IOT_STRCPY((char *)id, slot_name);

    return _storage->impl_func.del(_storage, id);
}

/********************************************************************************/
void
_hsm_deinit(void) {
    if (_storage && _storage->impl_func.deinit) {
        _storage->impl_func.deinit(_storage->impl_data);
    }
}

/******************************************************************************/
vs_status_e
_fill_slots_impl(vs_hsm_impl_t *hsm_impl, vs_storage_op_ctx_t *slots_storage_impl) {
    CHECK_NOT_ZERO_RET(hsm_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(slots_storage_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);

    _storage = slots_storage_impl;

    hsm_impl->deinit = _hsm_deinit;

    hsm_impl->slot_load = vs_hsm_slot_load;
    hsm_impl->slot_save = vs_hsm_slot_save;
    hsm_impl->slot_clean = vs_hsm_slot_delete;

    return VS_CODE_OK;
}

/******************************************************************************/
