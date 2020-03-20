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

#include "private/visibility.h"
#include <virgil/iot/messenger/crypto/msgr-crypto.h>


#include "vscf_recipient_cipher.h"
#include "vscf_key_provider.h"
#include "vscf_fake_random.h"
#include "vscf_aes256_gcm.h"
#include "vscf_random_padding.h"


/******************************************************************************/
DLL_PUBLIC vs_status_e
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
                            size_t *encrypted_data_sz) {

    vsc_data_t msg_data = vsc_data(data, data_sz);
    vsc_data_t recipient_pubkey_data = vsc_data(recipient_pubkey, recipient_pubkey_sz);
    vsc_data_t recipient_id_data = vsc_data(recepient_id, recepient_id_sz);
    vsc_data_t sender_privkey_data = vsc_data(sender_privkey, sender_privkey_sz);
    vsc_data_t sender_id_data = vsc_data(sender_id, sender_id_sz);


    //  Prepare random.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_impl_t *random = vscf_fake_random_impl(fake_random);

    //
    //  Prepare recipients / signers.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    if (vscf_status_SUCCESS != vscf_key_provider_setup_defaults(key_provider)) {
        assert(false);
    }

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, recipient_pubkey_data, &error);
    if (vscf_status_SUCCESS != vscf_error_status(&error)) {
        assert(false);
    }

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, sender_privkey_data, &error);
    if (vscf_status_SUCCESS != vscf_error_status(&error)) {
        assert(false);
    }

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, random);

    vscf_recipient_cipher_add_key_recipient(recipient_cipher, recipient_id_data, public_key);

    if (vscf_status_SUCCESS != vscf_recipient_cipher_add_signer(recipient_cipher, sender_id_data, private_key)) {
        assert(false);
    }

    //
    //  Encrypt.
    //
    if (vscf_status_SUCCESS != vscf_recipient_cipher_start_signed_encryption(recipient_cipher, msg_data.len)) {
        assert(false);
    }

    size_t message_info_len = vscf_recipient_cipher_message_info_len(recipient_cipher);
    size_t enc_msg_data_len = vscf_recipient_cipher_encryption_out_len(recipient_cipher, msg_data.len) +
                              vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

    vsc_buffer_t *enc_msg_header = vsc_buffer_new_with_capacity(message_info_len);
    vsc_buffer_t *enc_msg_data = vsc_buffer_new_with_capacity(enc_msg_data_len);

    vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg_header);

    if (vscf_status_SUCCESS != vscf_recipient_cipher_process_encryption(recipient_cipher, msg_data, enc_msg_data)) {
        assert(false);
    }

    if (vscf_status_SUCCESS != vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg_data)) {
        assert(false);
    }

    size_t enc_msg_info_footer_len = vscf_recipient_cipher_message_info_footer_len(recipient_cipher);
    vsc_buffer_t *enc_msg_footer = vsc_buffer_new_with_capacity(enc_msg_info_footer_len);

    if (vscf_status_SUCCESS != vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, enc_msg_footer)) {
        assert(false);
    }

    vsc_data_t header_data = vsc_buffer_data(enc_msg_header);
    vsc_data_t res_data = vsc_buffer_data(enc_msg_data);
    vsc_data_t footer_data = vsc_buffer_data(enc_msg_footer);

    size_t full_sz = header_data.len + res_data.len + footer_data.len;

    if (full_sz <= buf_sz) {
        *encrypted_data_sz = full_sz;
        uint8_t *p = encrypted_data;

        memcpy(p, header_data.bytes, header_data.len);
        p += header_data.len;

        memcpy(p, res_data.bytes, res_data.len);
        p += res_data.len;

        memcpy(p, footer_data.bytes, footer_data.len);
    }

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&enc_msg_footer);
    vsc_buffer_destroy(&enc_msg_data);
    vsc_buffer_destroy(&enc_msg_header);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&random);

    return VS_CODE_OK;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
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
                            size_t *decrypted_data_sz) {

    vsc_data_t ciphertext = vsc_data(enc_data, enc_data_sz);
    vsc_data_t plaintext = vsc_data(decrypted_data, buf_sz);
    vsc_data_t recipient_id = vsc_data(recepient_id, recepient_id_sz);
    vsc_data_t recipient_private_key = vsc_data(privkey, privkey_sz);
    vsc_data_t signer_id = vsc_data(sender_id, sender_id_sz);
    vsc_data_t signature_verify_key = vsc_data(sender_pubkey, sender_pubkey_sz);

    //
    //  Prepare random.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_impl_t *random = vscf_fake_random_impl(fake_random);

    //
    //  Prepare recipients / verifiers.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    //    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));
    vscf_key_provider_setup_defaults(key_provider);

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, signature_verify_key, &error);
    //    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    vscf_error_status(&error);

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, recipient_private_key, &error);
    //    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    vscf_error_status(&error);


    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, random);

    //
    //  Decrypt.
    //
    //    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
    //                      vscf_recipient_cipher_start_decryption_with_key(
    //                              recipient_cipher, recipient_id, private_key, vsc_data_empty()));
    vscf_recipient_cipher_start_decryption_with_key(recipient_cipher, recipient_id, private_key, vsc_data_empty());

    size_t out_len = vscf_recipient_cipher_decryption_out_len(recipient_cipher, ciphertext.len);
    out_len += vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    vscf_status_t status = vscf_recipient_cipher_process_decryption(recipient_cipher, ciphertext, out);
    //    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    status = vscf_recipient_cipher_finish_decryption(recipient_cipher, out);
    //    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plaintext, out);

    //
    //  Verify.
    //
    //    TEST_ASSERT_TRUE(vscf_recipient_cipher_is_data_signed(recipient_cipher));
    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(recipient_cipher);
    //    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));
    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);

    //    TEST_ASSERT_EQUAL_DATA(signer_id, vscf_signer_info_signer_id(signer_info));
    const bool verified = vscf_recipient_cipher_verify_signer_info(recipient_cipher, signer_info, public_key);
    //    TEST_ASSERT_TRUE(verified);

    vsc_data_t res_data = vsc_buffer_data(out);
    if (res_data.len <= buf_sz) {
        *decrypted_data_sz = res_data.len;
        memcpy(decrypted_data, res_data.bytes, res_data.len);
    }

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&out);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&random);

    return VS_CODE_OK;
}

/******************************************************************************/
