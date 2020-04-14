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

#define VS_MESSENGER_VIRGIL_IDENTITY_SZ_MAX (128) /**< Maximum size of Messenger's User Identity */
#define VS_MESSENGER_VIRGIL_KEY_SZ_MAX (128)      /**< Maximum size of Messenger's User key */
#define VS_MESSENGER_VIRGIL_CARD_ID_SZ_MAX (128)  /**< Maximum size of Messenger's Card identifier */
#define VS_MESSENGER_VIRGIL_TOKEN_SZ_MAX (1024)   /**< Maximum size of Messenger's token */
#define VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ (8)      /**< Size of Public key ID */

/** User credentials */
typedef struct {
    uint8_t privkey[VS_MESSENGER_VIRGIL_KEY_SZ_MAX];     /**< Private key data */
    uint16_t privkey_sz;                                 /**< Private key size */
    uint8_t pubkey[VS_MESSENGER_VIRGIL_KEY_SZ_MAX];      /**< Public key data */
    uint16_t pubkey_sz;                                  /**< Public key size */
    uint8_t pubkey_id[VS_MESSENGER_VIRGIL_PUBKEY_ID_SZ]; /**< ID of Public key */
    char card_id[VS_MESSENGER_VIRGIL_CARD_ID_SZ_MAX];    /**< Card identifier string */
} vs_messenger_virgil_user_creds_t;

vs_status_e
vs_messenger_virgil_init(const char *service_base_url, const char *custom_ca);

vs_status_e
vs_messenger_virgil_sign_in(const vs_messenger_virgil_user_creds_t *creds);

vs_status_e
vs_messenger_virgil_sign_up(const char *identity, vs_messenger_virgil_user_creds_t *creds);

vs_status_e
vs_messenger_virgil_search(const char *identity);

vs_status_e
vs_messenger_virgil_get_xmpp_pass(char *pass, size_t pass_buf_sz);

vs_status_e
vs_messenger_virgil_decrypt_msg(const char *sender,
                                const char *encrypted_message,
                                uint8_t *decrypted_message,
                                size_t buf_sz,
                                size_t *decrypted_message_sz);

vs_status_e
vs_messenger_virgil_encrypt_msg(const char *recipient,
                                const char *message,
                                uint8_t *encrypted_message,
                                size_t buf_sz,
                                size_t *encrypted_message_sz);

vs_status_e
vs_messenger_virgil_logout(void);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_MESSENGER_VIRGIL_H
