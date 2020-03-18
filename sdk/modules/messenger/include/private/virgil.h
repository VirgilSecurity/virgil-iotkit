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

#ifndef VS_MESSENGER_VIRGIL_H
#define VS_MESSENGER_VIRGIL_H

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
vs_messenger_virgil_init(void);

vs_status_e
vs_messenger_virgil_sign_in(const char *identity,
                            const uint8_t *pubkey,
                            size_t pubkey_sz,
                            const uint8_t *privkey,
                            size_t privkey_sz,
                            const uint8_t *card,
                            size_t card_sz);

vs_status_e
vs_messenger_virgil_sign_up(const char *identity,
                            uint8_t *pubkey,
                            size_t pubkey_buf_sz,
                            size_t *pubkey_sz,
                            uint8_t *privkey,
                            size_t priv_buf_sz,
                            size_t *priv_sz,
                            uint8_t *card,
                            size_t card_buf_sz,
                            size_t *card_sz);

vs_status_e
vs_messenger_virgil_get_token(char *token, size_t token_buf_sz);

vs_status_e
vs_messenger_virgil_get_xmpp_pass(char *pass, size_t pass_buf_sz);

// Pay attention: msg buffer MUST be freed
vs_status_e
vs_messenger_virgil_decrypt_msg(const char *sender, const char *encrypted_message, char **msg);

vs_status_e
vs_messenger_virgil_logout(void);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_MESSENGER_VIRGIL_H
