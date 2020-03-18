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

#ifndef VS_MESSENGER_CRYPTO_H
#define VS_MESSENGER_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <global-hal.h>
#include <virgil/iot/status_code/status_code.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

vs_status_e
vs_messenger_crypto_encrypt(const uint8_t *data,
                            size_t data_sz,
                            const uint8_t *recipient_pubkey,
                            size_t recipient_pubkey_sz,
                            const uint8_t *recepient_id,
                            size_t recepient_id_sz,
                            const uint8_t *sender_privkey,
                            size_t sender_privkey_sz,
                            const uint8_t *sender_id,
                            size_t sender_id_sz,
                            uint8_t *encrypted_data,
                            size_t buf_sz,
                            size_t *encrypted_data_sz);

vs_status_e
vs_messenger_crypto_decrypt(const uint8_t *enc_data,
                            size_t enc_data_sz,
                            const uint8_t *privkey,
                            size_t privkey_sz,
                            const uint8_t *recepient_id,
                            size_t recepient_id_sz,
                            const uint8_t *sender_pubkey,
                            size_t sender_pubkey_sz,
                            const uint8_t *sender_id,
                            size_t sender_id_sz,
                            uint8_t *decrypted_data,
                            size_t buf_sz,
                            size_t *decrypted_data_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_MESSENGER_CRYPTO_H
