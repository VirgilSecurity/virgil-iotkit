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

#include <stdlib.h>

#include <global-hal.h>
#include <update-config.h>
#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/macros/macros.h>

#include <virgil/iot/update/update.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/hsm/hsm_sw_sha2_routines.h>

#define TEST_REC_KEYPAIR VS_KEY_SLOT_STD_MTP_12
#define TEST_AUTH_KEYPAIR VS_KEY_SLOT_STD_MTP_13
#define TEST_FW_KEYPAIR VS_KEY_SLOT_STD_MTP_14

#define VS_TEST_FIRMWARE_DATA "test firmware data for verifying update library"
#define VS_TEST_FILL_SIZE 256

static uint8_t *_fw_footer = NULL;

#define GW_MANUFACTURE_ID                                                                                              \
    { 'V', 'R', 'G', 'L' }
#define GW_DEVICE_TYPE                                                                                                 \
    { 'T', 'E', 'S', 'T' }
#define GW_APP_TYPE                                                                                                    \
    { 'A', 'P', 'P', '0' }

static const vs_firmware_descriptor_t _test_descriptor = {
        .info.manufacture_id = GW_MANUFACTURE_ID,
        .info.device_type = GW_DEVICE_TYPE,
        .info.version.app_type = GW_APP_TYPE,
        .info.version.major = 0,
        .info.version.minor = 1,
        .info.version.patch = 3,
        .info.version.dev_milestone = 'm',
        .info.version.dev_build = 0,
        .info.version.timestamp = 0,
        .padding = 0,
        .chunk_size = 256,
        .firmware_length = strlen(VS_TEST_FIRMWARE_DATA),
        .app_size = strlen(VS_TEST_FIRMWARE_DATA) + VS_TEST_FILL_SIZE,
};

/**********************************************************/
static bool
_create_test_signed_hl_key(vs_key_type_e hl_key_type,
                           vs_iot_hsm_slot_e slot_with_hl_keypair,
                           vs_iot_hsm_slot_e slot_to_save_pubkey,
                           bool with_signature) {
    uint8_t buf[PUBKEY_MAX_BUF_SIZE];
    uint8_t hash_buf[32];
    int key_len = vs_hsm_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    int sign_len = vs_hsm_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    uint16_t hl_slot_sz = sizeof(vs_pubkey_dated_t) + sizeof(vs_pubkey_t) + key_len + sign_len;
    vs_pubkey_dated_t *hl_key = (vs_pubkey_dated_t *)buf;
    vs_hsm_keypair_type_e pubkey_type;
    uint16_t _sz;

    VS_IOT_MEMSET(buf, 0, sizeof(buf));
    hl_key->start_date = 0;
    hl_key->expire_date = UINT32_MAX;
    hl_key->pubkey.ec_type = VS_KEYPAIR_EC_SECP256R1;
    hl_key->pubkey.key_type = hl_key_type;

    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_keypair_get_pubkey(
                                            slot_with_hl_keypair, hl_key->pubkey.pubkey, key_len, &_sz, &pubkey_type),
                   "Error get test pubkey")

    if (with_signature) {
        VS_HSM_CHECK_RET(vs_hsm_hash_create(VS_HASH_SHA_256,
                                            buf,
                                            sizeof(vs_pubkey_dated_t) + sizeof(vs_pubkey_t) + key_len,
                                            hash_buf,
                                            sizeof(hash_buf),
                                            &_sz),
                         "ERROR while creating hash for test key")

        BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_ecdsa_sign(TEST_REC_KEYPAIR,
                                                          VS_HASH_SHA_256,
                                                          hash_buf,
                                                          hl_key->pubkey.pubkey + key_len,
                                                          sign_len,
                                                          &_sz),
                       "Error sign test pubkey")
    }
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_slot_save(slot_to_save_pubkey, buf, hl_slot_sz), "Error save test pubkey")
    return true;
}

/**********************************************************/
static bool
_create_test_hl_keys() {
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_keypair_create(TEST_REC_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test recovery keypair")
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_keypair_create(TEST_AUTH_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test auth keypair")
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_keypair_create(TEST_FW_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create fw keypair")

    BOOL_CHECK_RET(_create_test_signed_hl_key(VS_KEY_RECOVERY, TEST_REC_KEYPAIR, REC1_KEY_SLOT, false),
                   "Error while creating signed test rec key")
    BOOL_CHECK_RET(_create_test_signed_hl_key(VS_KEY_AUTH, TEST_AUTH_KEYPAIR, AUTH1_KEY_SLOT, true),
                   "Error while creating signed test auth key")
    BOOL_CHECK_RET(_create_test_signed_hl_key(VS_KEY_FIRMWARE, TEST_FW_KEYPAIR, FW1_KEY_SLOT, true),
                   "Error while creating signed test auth key")

    return true;
}

/**********************************************************/
static bool
_create_test_firmware_signature(vs_key_type_e signer_type,
                                vs_iot_hsm_slot_e slot_with_hl_keypair,
                                uint8_t fw_hash[32],
                                vs_sign_t *sign_buf) {
    int sign_len = vs_hsm_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    int key_len = vs_hsm_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    uint16_t _sz;
    vs_hsm_keypair_type_e pubkey_type;

    sign_buf->signer_type = signer_type;
    sign_buf->ec_type = VS_KEYPAIR_EC_SECP256R1;
    sign_buf->hash_type = VS_HASH_SHA_256;

    BOOL_CHECK_RET(
            VS_HSM_ERR_OK ==
                    vs_hsm_ecdsa_sign(
                            slot_with_hl_keypair, VS_HASH_SHA_256, fw_hash, sign_buf->raw_sign_pubkey, sign_len, &_sz),
            "Error sign test firmware by auth key")
    BOOL_CHECK_RET(
            VS_HSM_ERR_OK ==
                    vs_hsm_keypair_get_pubkey(
                            slot_with_hl_keypair, sign_buf->raw_sign_pubkey + sign_len, key_len, &_sz, &pubkey_type),
            "Error get test aut pubkey")
    return true;
}

/**********************************************************/
static bool
_create_test_firmware_footer() {
    vs_update_firmware_footer_t *footer;
    int key_len = vs_hsm_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    int sign_len = vs_hsm_get_signature_len(VS_KEYPAIR_EC_SECP256R1);

    uint8_t fill[VS_TEST_FILL_SIZE];
    VS_IOT_MEMSET(fill, 0xFF, sizeof(fill));

    _fw_footer = VS_IOT_MALLOC(sizeof(vs_update_firmware_footer_t) +
                               VS_FW_SIGNATURES_QTY * (sizeof(vs_sign_t) + key_len + sign_len));
    if (NULL == _fw_footer) {
        VS_LOG_ERROR("Error while memory alloc");
        return false;
    }

    footer = (vs_update_firmware_footer_t *)_fw_footer;

    vs_hsm_sw_sha256_ctx hash_ctx;
    uint8_t hash[32];
    vs_hsm_sw_sha256_init(&hash_ctx);

    footer->signatures_count = VS_FW_SIGNATURES_QTY;
    VS_IOT_MEMCPY(&footer->descriptor, &_test_descriptor, sizeof(vs_firmware_descriptor_t));

    vs_hsm_sw_sha256_update(&hash_ctx, (uint8_t *)VS_TEST_FIRMWARE_DATA, strlen(VS_TEST_FIRMWARE_DATA));
    vs_hsm_sw_sha256_update(&hash_ctx, fill, sizeof(fill));
    vs_hsm_sw_sha256_update(&hash_ctx, _fw_footer, sizeof(vs_update_firmware_footer_t));
    vs_hsm_sw_sha256_final(&hash_ctx, hash);

    vs_sign_t *sign = (vs_sign_t *)footer->signatures;

    BOOL_CHECK_RET(_create_test_firmware_signature(VS_KEY_AUTH, TEST_AUTH_KEYPAIR, hash, sign),
                   "Error while creating auth signature")

    sign = (vs_sign_t *)(sign->raw_sign_pubkey + sign_len + key_len);

    BOOL_CHECK_RET(_create_test_firmware_signature(VS_KEY_FIRMWARE, TEST_FW_KEYPAIR, hash, sign),
                   "Error while creating fw signature")

    return true;
}
/**********************************************************/
static bool
_test_firmware_save() {

    return true;
}

/**********************************************************/
uint16_t
vs_update_test(vs_storage_op_ctx_t *ctx) {
    uint16_t failed_test_result = 0;

    START_TEST("Update tests");

    TEST_CASE_OK("Prepare keystorage for test", vs_test_erase_otp_provision() && vs_test_create_device_key())
    TEST_CASE_OK("Create hl keys for test", _create_test_hl_keys())
    TEST_CASE_OK("Create test firmware footer", _create_test_firmware_footer())
    TEST_CASE_OK("Save firmware image", _test_firmware_save())

    if (VS_STORAGE_OK != vs_update_init(ctx)) {
        RESULT_ERROR;
    }

terminate:
    if (_fw_footer) {
        VS_IOT_FREE(_fw_footer);
    }

    vs_update_deinit(ctx);
    return failed_test_result;
}