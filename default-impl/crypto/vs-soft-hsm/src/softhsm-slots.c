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

/********************************************************************************/
static vs_status_e
vs_hsm_slot_save(vs_iot_hsm_slot_e slot, const uint8_t *data, uint16_t data_sz) {
    return vs_rpi_write_file_data(slots_dir, get_slot_name(slot), 0, data, data_sz) &&
           vs_rpi_sync_file(slots_dir, get_slot_name(slot))
           ? VS_CODE_OK
           : VS_CODE_ERR_FILE_WRITE;
}

/********************************************************************************/
static vs_status_e
vs_hsm_slot_load(vs_iot_hsm_slot_e slot, uint8_t *data, uint16_t buf_sz, uint16_t *out_sz) {
    size_t out_sz_size_t = *out_sz;
    vs_status_e call_res;

    call_res = vs_rpi_read_file_data(slots_dir, get_slot_name(slot), 0, data, buf_sz, &out_sz_size_t)
               ? VS_CODE_OK
               : VS_CODE_ERR_FILE_READ;

    assert(out_sz_size_t <= UINT16_MAX);
    *out_sz = out_sz_size_t;

    return call_res;
}

/******************************************************************************/
static vs_status_e
vs_hsm_slot_delete(vs_iot_hsm_slot_e slot) {
    return vs_rpi_remove_file_data(slots_dir, get_slot_name(slot)) ? VS_CODE_OK : VS_CODE_ERR_FILE_DELETE;
}

/******************************************************************************/
