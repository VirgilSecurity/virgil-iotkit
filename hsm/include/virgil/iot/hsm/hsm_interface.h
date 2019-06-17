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

#ifndef VS_HSM_INTERFACE_API_H
#define VS_HSM_INTERFACE_API_H

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/hsm/hsm_structs.h>
#include <virgil/iot/hsm/hsm_errors.h>

int
vs_hsm_slot_save(vs_iot_hsm_slot_e slot, const uint8_t *in_data, uint16_t data_sz);
int
vs_hsm_slot_load(vs_iot_hsm_slot_e slot, uint8_t *out_data, uint16_t buf_sz, uint16_t *out_sz);

int
vs_hsm_hash_create(vs_hsm_hash_type_e hash_type,
                   const uint8_t *data,
                   uint16_t data_sz,
                   uint8_t *hash,
                   uint16_t hash_buf_sz,
                   uint16_t *hash_sz);

int
vs_hsm_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type);
int
vs_hsm_keypair_get_pubkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type);
int
vs_hsm_ecdsa_sign(vs_iot_hsm_slot_e key_slot,
                  vs_hsm_hash_type_e hash_type,
                  const uint8_t *hash,
                  uint8_t *signature,
                  uint16_t signature_buf_sz,
                  uint16_t *signature_sz);
int
vs_hsm_ecdsa_verify(vs_hsm_keypair_type_e keypair_type,
                    const uint8_t *public_key,
                    uint16_t public_key_sz,
                    vs_hsm_hash_type_e hash_type,
                    const uint8_t *hash,
                    const uint8_t *signature,
                    uint16_t signature_sz);

int
vs_hsm_hmac(vs_hsm_hash_type_e hash_type,
            const uint8_t *key,
            uint16_t key_sz,
            const uint8_t *input,
            uint16_t input_sz,
            uint8_t *output,
            uint16_t output_buf_sz,
            uint16_t *output_sz);

int
vs_hsm_kdf(vs_hsm_kdf_type_e kdf_type,
           vs_hsm_hash_type_e hash_type,
           const uint8_t *input,
           uint16_t input_sz,
           uint8_t *output,
           uint16_t output_sz);

#endif // VS_HSM_INTERFACE_API_H
