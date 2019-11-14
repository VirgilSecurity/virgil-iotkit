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

#ifndef VS_SOFT_SECMODULE_PRIVATE_H
#define VS_SOFT_SECMODULE_PRIVATE_H

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/storage_hal/storage_hal.h>

#define MAX_KEY_SZ (128)

#define CHECK_VSCF(OPERATION, DESCRIPTION, ...)                                                                        \
    CHECK_BOOL((vscf_status_SUCCESS == (OPERATION)), DESCRIPTION, ##__VA_ARGS__)

const vs_secmodule_impl_t *
_soft_secmodule_intern(void);

const char *
get_slot_name(vs_iot_secmodule_slot_e slot);

int
vs_secmodule_keypair_get_prvkey(vs_iot_secmodule_slot_e slot,
                                uint8_t *buf,
                                uint16_t buf_sz,
                                uint16_t *key_sz,
                                vs_secmodule_keypair_type_e *keypair_type);

vs_status_e
_fill_slots_impl(vs_secmodule_impl_t *secmodule_impl, vs_storage_op_ctx_t *slots_storage_impl);

vs_status_e
_fill_crypto_impl(vs_secmodule_impl_t *secmodule_impl);

vs_status_e
_fill_keypair_impl(vs_secmodule_impl_t *secmodule_impl);

vs_status_e
_fill_soft_hash_impl(vs_secmodule_impl_t *secmodule_impl);

void
_secmodule_deinit(void);


#endif // VS_SOFT_SECMODULE_PRIVATE_H
