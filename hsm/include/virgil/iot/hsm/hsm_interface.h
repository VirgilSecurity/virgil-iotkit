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

#ifndef VS_HSM_API_H
#define VS_HSM_API_H
#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/hsm/hsm_structs.h>
#include <virgil/iot/hsm/devices/hsm_none.h>
#include <virgil/iot/hsm/devices/hsm_custom.h>
#include <virgil/iot/hsm/devices/hsm_atecc_508a.h>
#include <virgil/iot/hsm/devices/hsm_atecc_608a.h>
#include <virgil/iot/hsm/devices/hsm_iotelic.h>

int
vs_hsm_slot_save(vs_iot_hsm_slot_e slot, const uint8_t *in_data, size_t data_sz);
int
vs_hsm_slot_load(vs_iot_hsm_slot_e slot, uint8_t *out_data, size_t buf_sz, int16_t *out_sz);
int
vs_hsm_hash_create(vs_hsm_hash_type hash_type,
            const uint8_t *data,
            size_t data_sz,
            uint8_t *hash,
            size_t hash_buf_sz,
            uint16_t *hash_sz);

#endif // VS_HSM_API_H
