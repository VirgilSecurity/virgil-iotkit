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

#include <stdio.h>
#include <virgil/iot/tests/helpers.h>
#include <private/private_helpers.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

/******************************************************************************/
static bool
_test_ecdh_pass(vs_secmodule_impl_t *secmodule_impl,
                vs_secmodule_keypair_type_e keypair_type,
                bool corrupt_key,
                vs_iot_secmodule_slot_e alice_slot,
                vs_iot_secmodule_slot_e bob_slot) {

    uint8_t alice_public_key[256] = {0};
    uint16_t alice_public_key_sz = 0;
    vs_secmodule_keypair_type_e alice_keypair_type = VS_KEYPAIR_INVALID;

    uint8_t bob_public_key[256] = {0};
    uint16_t bob_public_key_sz = 0;
    vs_secmodule_keypair_type_e bob_keypair_type = VS_KEYPAIR_INVALID;

    uint8_t shared_secret_1[128] = {0};
    uint16_t shared_secret_sz_1 = 0;

    uint8_t shared_secret_2[128] = {0};
    uint16_t shared_secret_sz_2 = 0;


    // Create key pair for Alice
    STATUS_CHECK_RET_BOOL(secmodule_impl->create_keypair(alice_slot, keypair_type),
                          "Can't create keypair %s for Alice",
                          vs_secmodule_keypair_type_descr(keypair_type));

    STATUS_CHECK_RET_BOOL(
            secmodule_impl->get_pubkey(
                    alice_slot, alice_public_key, sizeof(alice_public_key), &alice_public_key_sz, &alice_keypair_type),
            "Can't load public key from slot %s for Alice",
            vs_test_secmodule_slot_descr(alice_slot));

    if (corrupt_key) {
        ++alice_public_key[1];
    }

    // Create key pair for Bob
    STATUS_CHECK_RET_BOOL(secmodule_impl->create_keypair(bob_slot, keypair_type),
                          "Can't create keypair %s for Bob",
                          vs_secmodule_keypair_type_descr(keypair_type));

    STATUS_CHECK_RET_BOOL(
            secmodule_impl->get_pubkey(
                    bob_slot, bob_public_key, sizeof(bob_public_key), &bob_public_key_sz, &bob_keypair_type),
            "Can't load public key from slot %s for Bob",
            vs_test_secmodule_slot_descr(bob_slot));

    // ECDH for Alice - Bob
    STATUS_CHECK_RET_BOOL(secmodule_impl->ecdh(alice_slot,
                                               bob_keypair_type,
                                               bob_public_key,
                                               bob_public_key_sz,
                                               shared_secret_1,
                                               sizeof(shared_secret_1),
                                               &shared_secret_sz_1),
                          "Can't process ECDH (slot %s, keypair type %s) for Alice",
                          vs_test_secmodule_slot_descr(alice_slot),
                          vs_secmodule_keypair_type_descr(bob_keypair_type));

    // ECDH for Bob - Alice
    if (VS_CODE_OK != secmodule_impl->ecdh(bob_slot,
                                           alice_keypair_type,
                                           alice_public_key,
                                           alice_public_key_sz,
                                           shared_secret_2,
                                           sizeof(shared_secret_2),
                                           &shared_secret_sz_2)) {
        if (!corrupt_key) {
            VS_LOG_ERROR("Can't process ECDH (slot %s, keypair type %s) for Bob",
                         vs_test_secmodule_slot_descr(bob_slot),
                         vs_secmodule_keypair_type_descr(alice_keypair_type));
        }

        return false;
    }

    // Compare shared secrets
    if (shared_secret_sz_1 != shared_secret_sz_2) {
        if (!corrupt_key) {
            VS_LOG_ERROR("Shared secret sizes are not equal");
        }

        return false;
    }

    if (memcmp(shared_secret_1, shared_secret_2, shared_secret_sz_1) != 0) {
        if (!corrupt_key) {
            VS_LOG_ERROR("Shared secret sequences are not equal");
        }
        return false;
    }

    return true;
}

/******************************************************************************/
static bool
_prepare_and_test(vs_secmodule_impl_t *secmodule_impl,
                  char *descr,
                  vs_secmodule_keypair_type_e keypair_type,
                  vs_iot_secmodule_slot_e alice_slot,
                  vs_iot_secmodule_slot_e bob_slot,
                  bool corrupt) {
    bool not_implemented = false;

    VS_IOT_STRCPY(descr, "Key ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_secmodule_keypair_type_descr(keypair_type));
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", Alice's slot ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_test_secmodule_slot_descr(alice_slot));
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", Bob's slot ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_test_secmodule_slot_descr(bob_slot));
    if (corrupt) {
        VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", key corruption");
    }

    TEST_KEYPAIR_NOT_IMPLEMENTED(alice_slot, keypair_type);
    if (not_implemented) {
        VS_LOG_WARNING("Keypair type %s is not implemented", vs_secmodule_keypair_type_descr(keypair_type));
        return false;
    }

    TEST_ECDH_NOT_IMPLEMENTED(alice_slot, keypair_type);
    if (not_implemented) {
        VS_LOG_WARNING("ECDH for keypair type %s is not implemented", vs_secmodule_keypair_type_descr(keypair_type));
        return false;
    }

    return true;
}

/******************************************************************************/
uint16_t
test_ecdh(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;

    char descr[256];

    START_TEST("ECDH tests");

#define TEST_ECDH_PASS(KEY, SLOT_ALICE, SLOT_BOB, CORRUPT)                                                             \
    do {                                                                                                               \
                                                                                                                       \
        if (_prepare_and_test(secmodule_impl, descr, (KEY), (SLOT_ALICE), (SLOT_BOB), (CORRUPT))) {                    \
            if (CORRUPT) {                                                                                             \
                TEST_CASE_NOT_OK(descr, _test_ecdh_pass(secmodule_impl, KEY, CORRUPT, SLOT_ALICE, SLOT_BOB));          \
            } else {                                                                                                   \
                TEST_CASE_OK(descr, _test_ecdh_pass(secmodule_impl, KEY, CORRUPT, SLOT_ALICE, SLOT_BOB));              \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

    TEST_ECDH_PASS(VS_KEYPAIR_EC_SECP256R1, VS_KEY_SLOT_STD_MTP_1, VS_KEY_SLOT_STD_MTP_2, false);
    TEST_ECDH_PASS(VS_KEYPAIR_EC_SECP384R1, VS_KEY_SLOT_STD_MTP_1, VS_KEY_SLOT_STD_MTP_2, false);
    TEST_ECDH_PASS(VS_KEYPAIR_EC_SECP521R1, VS_KEY_SLOT_EXT_MTP_0, VS_KEY_SLOT_EXT_TMP_0, false);
    TEST_ECDH_PASS(VS_KEYPAIR_EC_ED25519, VS_KEY_SLOT_STD_MTP_1, VS_KEY_SLOT_STD_MTP_2, false);
    TEST_ECDH_PASS(VS_KEYPAIR_EC_CURVE25519, VS_KEY_SLOT_STD_MTP_1, VS_KEY_SLOT_STD_MTP_2, false);
    TEST_ECDH_PASS(VS_KEYPAIR_EC_SECP256R1, VS_KEY_SLOT_STD_MTP_1, VS_KEY_SLOT_STD_MTP_2, true);
    TEST_ECDH_PASS(VS_KEYPAIR_EC_CURVE25519, VS_KEY_SLOT_STD_MTP_1, VS_KEY_SLOT_STD_MTP_2, true);

terminate:
    return failed_test_result;
#undef TEST_ECDH_OK_PASS
#undef TEST_ECDH_NOT_OK_PASS
}
