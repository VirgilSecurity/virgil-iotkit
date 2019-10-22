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

#include <virgil/iot/hsm/hsm.h>
#include <virgil/iot/provision/provision-structs.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/storage_hal/storage_hal.h>

vs_status_e
vs_provision_init(vs_storage_op_ctx_t *tl_storage_ctx, vs_hsm_impl_t *hsm);

vs_status_e
vs_provision_deinit(void);

vs_status_e
vs_provision_get_slot_num(vs_provision_element_id_e id, uint16_t *slot);

vs_status_e
vs_provision_search_hl_pubkey(vs_key_type_e key_type, vs_hsm_keypair_type_e ec_type, uint8_t *key, uint16_t key_sz);

vs_status_e
vs_provision_verify_hl_key(const uint8_t *key_to_check, uint16_t key_size);

const char *
vs_provision_cloud_url(void);

vs_status_e
vs_provision_tl_find_first_key(vs_provision_tl_find_ctx_t *search_ctx,
                               vs_key_type_e key_type,
                               uint8_t **pubkey,
                               uint16_t *pubkey_sz,
                               uint8_t **meta,
                               uint16_t *meta_sz);

vs_status_e
vs_provision_tl_find_next_key(vs_provision_tl_find_ctx_t *search_ctx,
                              uint8_t **pubkey,
                              uint16_t *pubkey_sz,
                              uint8_t **meta,
                              uint16_t *meta_sz);

#endif // VS_IOT_PROVISION_H