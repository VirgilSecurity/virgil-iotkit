//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#ifndef VS_SECMODULE_ASN1_CRYPTOGRAM_H
#define VS_SECMODULE_ASN1_CRYPTOGRAM_H

#include <stdint.h>
#include <virgil/iot/status_code/status_code.h>

vs_status_e
vs_secmodule_virgil_cryptogram_parse_sha384_aes256(const uint8_t *cryptogram,
                                                   size_t cryptogram_sz,
                                                   const uint8_t *recipient_id,
                                                   size_t recipient_id_sz,
                                                   uint8_t **public_key,
                                                   uint8_t **iv_key,
                                                   uint8_t **encrypted_key,
                                                   uint8_t **mac_data,
                                                   uint8_t **iv_data,
                                                   uint8_t **encrypted_data,
                                                   size_t *encrypted_data_sz);

vs_status_e
vs_secmodule_virgil_cryptogram_create_sha384_aes256(const uint8_t *recipient_id,
                                                    size_t recipient_id_sz,
                                                    size_t encrypted_data_sz,
                                                    const uint8_t *encrypted_data,
                                                    const uint8_t *iv_data,
                                                    const uint8_t *encrypted_key,
                                                    const uint8_t *iv_key,
                                                    const uint8_t *hmac,
                                                    const uint8_t *public_key,
                                                    size_t public_key_sz,
                                                    uint8_t *cryptogram,
                                                    size_t cryptogram_buf_sz,
                                                    size_t *cryptogram_sz);


#endif // VS_SECMODULE_ASN1_CRYPTOGRAM_H
