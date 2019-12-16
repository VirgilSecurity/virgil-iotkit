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

#include <virgil/iot/vs-soft-provision/vs-soft-provision.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/macros/macros.h>

static vs_status_e
_get_slot_num(vs_provision_element_id_e id, uint16_t *slot);
static vs_status_e
_save_element(vs_secmodule_impl_t *secmodule, vs_provision_element_id_e id, const uint8_t *data, uint16_t data_sz);
static vs_status_e
_load_element(vs_secmodule_impl_t *secmodule,
              vs_provision_element_id_e id,
              uint8_t *buf,
              uint16_t buf_sz,
              uint16_t *element_sz);

static const vs_provision_impl_t _impl = {.get_slot_num = _get_slot_num,
                                          .save_element = _save_element,
                                          .load_element = _load_element};

/******************************************************************************/
static vs_status_e
_get_slot_num(vs_provision_element_id_e id, uint16_t *slot) {
    CHECK_NOT_ZERO_RET(slot, VS_CODE_ERR_NULLPTR_ARGUMENT);

    switch (id) {
    case VS_PROVISION_PBR1:
        *slot = REC1_KEY_SLOT;
        break;
    case VS_PROVISION_PBR2:
        *slot = REC2_KEY_SLOT;
        break;
    case VS_PROVISION_PBA1:
        *slot = AUTH1_KEY_SLOT;
        break;
    case VS_PROVISION_PBA2:
        *slot = AUTH2_KEY_SLOT;
        break;
    case VS_PROVISION_PBT1:
        *slot = TL1_KEY_SLOT;
        break;
    case VS_PROVISION_PBT2:
        *slot = TL2_KEY_SLOT;
        break;
    case VS_PROVISION_PBF1:
        *slot = FW1_KEY_SLOT;
        break;
    case VS_PROVISION_PBF2:
        *slot = FW2_KEY_SLOT;
        break;
    case VS_PROVISION_SGNP:
        *slot = SIGNATURE_SLOT;
        break;
    default:
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }
    return VS_CODE_OK;
}


/******************************************************************************/
static vs_status_e
_save_element(vs_secmodule_impl_t *secmodule, vs_provision_element_id_e id, const uint8_t *data, uint16_t data_sz) {
    uint16_t slot;
    vs_status_e ret_code;
    CHECK_NOT_ZERO_RET(secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    STATUS_CHECK_RET(_get_slot_num(id, &slot), "Incorrect provision element id");

    return secmodule->slot_save(slot, data, data_sz);
}


/******************************************************************************/
static vs_status_e
_load_element(vs_secmodule_impl_t *secmodule,
              vs_provision_element_id_e id,
              uint8_t *buf,
              uint16_t buf_sz,
              uint16_t *element_sz) {
    uint16_t slot;
    vs_status_e ret_code;
    CHECK_NOT_ZERO_RET(secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(element_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    STATUS_CHECK_RET(_get_slot_num(id, &slot), "Incorrect provision element id");

    return secmodule->slot_load(slot, buf, buf_sz, element_sz);
}

/******************************************************************************/
const vs_provision_impl_t *
vs_soft_provision_impl(void) {
    return &_impl;
}
