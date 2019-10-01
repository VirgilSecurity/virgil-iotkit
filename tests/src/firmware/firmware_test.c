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

#include <virgil/iot/firmware/firmware.h>
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

#define TEST_MANUFACTURE_ID                                                                                            \
    { 'V', 'R', 'G', 'L' }
#define TEST_DEVICE_TYPE                                                                                               \
    { 'T', 'E', 'S', 'T' }
#define TEST_APP_TYPE                                                                                                  \
    { 'A', 'P', 'P', '0' }

static vs_firmware_descriptor_t _test_descriptor = {
        .info.manufacture_id = TEST_MANUFACTURE_ID,
        .info.device_type = TEST_DEVICE_TYPE,
        .info.version.app_type = TEST_APP_TYPE,
        .info.version.major = 0,
        .info.version.minor = 1,
        .info.version.patch = 3,
        .info.version.dev_milestone = 'm',
        .info.version.dev_build = 0,
        .info.version.timestamp = 0,
        .padding = 0,
        .chunk_size = 256,
        .firmware_length = sizeof(VS_TEST_FIRMWARE_DATA),
        .app_size = sizeof(VS_TEST_FIRMWARE_DATA) + VS_TEST_FILL_SIZE,
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
    uint16_t hl_slot_sz = sizeof(vs_pubkey_dated_t) + key_len + sizeof(vs_sign_t) + sign_len + key_len;
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
                   "Error get test pubkey");

    if (with_signature) {
        VS_HSM_CHECK_RET(
                vs_hsm_hash_create(
                        VS_HASH_SHA_256, buf, sizeof(vs_pubkey_dated_t) + key_len, hash_buf, sizeof(hash_buf), &_sz),
                "ERROR while creating hash for test key");

        vs_sign_t *sign = (vs_sign_t *)(hl_key->pubkey.pubkey + key_len);
        sign->signer_type = VS_KEY_RECOVERY;
        sign->hash_type = VS_HASH_SHA_256;
        sign->ec_type = VS_KEYPAIR_EC_SECP256R1;

        BOOL_CHECK_RET(
                VS_HSM_ERR_OK ==
                        vs_hsm_ecdsa_sign(
                                TEST_REC_KEYPAIR, VS_HASH_SHA_256, hash_buf, sign->raw_sign_pubkey, sign_len, &_sz),
                "Error sign test pubkey");

        BOOL_CHECK_RET(VS_HSM_ERR_OK ==
                               vs_hsm_keypair_get_pubkey(
                                       TEST_REC_KEYPAIR, sign->raw_sign_pubkey + sign_len, key_len, &_sz, &pubkey_type),
                       "Error get test RECOVERY pubkey");
    }
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_slot_save(slot_to_save_pubkey, buf, hl_slot_sz), "Error save test pubkey");
    return true;
}

/**********************************************************/
static bool
_create_test_hl_keys() {
    VS_HEADER_SUBCASE("Create test hl keys");
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_keypair_create(TEST_REC_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test recovery keypair");
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_keypair_create(TEST_AUTH_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test auth keypair");
    BOOL_CHECK_RET(VS_HSM_ERR_OK == vs_hsm_keypair_create(TEST_FW_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create fw keypair");

    BOOL_CHECK_RET(_create_test_signed_hl_key(VS_KEY_RECOVERY, TEST_REC_KEYPAIR, REC1_KEY_SLOT, false),
                   "Error while creating signed test rec key");
    BOOL_CHECK_RET(_create_test_signed_hl_key(VS_KEY_AUTH, TEST_AUTH_KEYPAIR, AUTH1_KEY_SLOT, true),
                   "Error while creating signed test auth key");
    BOOL_CHECK_RET(_create_test_signed_hl_key(VS_KEY_FIRMWARE, TEST_FW_KEYPAIR, FW1_KEY_SLOT, true),
                   "Error while creating signed test auth key");

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
            "Error sign test firmware by auth key");
    BOOL_CHECK_RET(
            VS_HSM_ERR_OK ==
                    vs_hsm_keypair_get_pubkey(
                            slot_with_hl_keypair, sign_buf->raw_sign_pubkey + sign_len, key_len, &_sz, &pubkey_type),
            "Error get test aut pubkey");
    return true;
}

/**********************************************************/
static bool
_create_test_firmware_footer() {
    vs_firmware_footer_t *footer;
    int key_len = vs_hsm_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    int sign_len = vs_hsm_get_signature_len(VS_KEYPAIR_EC_SECP256R1);

    uint8_t fill[VS_TEST_FILL_SIZE];
    VS_IOT_MEMSET(fill, 0xFF, sizeof(fill));

    VS_HEADER_SUBCASE("Create test firmware footer");
    uint16_t footer_sz =
            sizeof(vs_firmware_footer_t) + VS_FW_SIGNATURES_QTY * (sizeof(vs_sign_t) + key_len + sign_len);
    _fw_footer = VS_IOT_MALLOC(footer_sz);
    _test_descriptor.app_size += footer_sz;
    if (NULL == _fw_footer) {
        VS_LOG_ERROR("Error while memory alloc");
        return false;
    }

    footer = (vs_firmware_footer_t *)_fw_footer;

    vs_hsm_sw_sha256_ctx hash_ctx;
    uint8_t hash[32];
    vs_hsm_sw_sha256_init(&hash_ctx);

    footer->signatures_count = VS_FW_SIGNATURES_QTY;
    VS_IOT_MEMCPY(&footer->descriptor, &_test_descriptor, sizeof(vs_firmware_descriptor_t));

    vs_hsm_sw_sha256_update(&hash_ctx, (uint8_t *)VS_TEST_FIRMWARE_DATA, sizeof(VS_TEST_FIRMWARE_DATA));
    vs_hsm_sw_sha256_update(&hash_ctx, fill, sizeof(fill));
    vs_hsm_sw_sha256_update(&hash_ctx, _fw_footer, sizeof(vs_firmware_footer_t));
    vs_hsm_sw_sha256_final(&hash_ctx, hash);

    vs_sign_t *sign = (vs_sign_t *)footer->signatures;

    BOOL_CHECK_RET(_create_test_firmware_signature(VS_KEY_AUTH, TEST_AUTH_KEYPAIR, hash, sign),
                   "Error while creating auth signature");

    sign = (vs_sign_t *)(sign->raw_sign_pubkey + sign_len + key_len);

    BOOL_CHECK_RET(_create_test_firmware_signature(VS_KEY_FIRMWARE, TEST_FW_KEYPAIR, hash, sign),
                   "Error while creating fw signature");

    return true;
}
/**********************************************************/
static bool
_test_firmware_save_load_descriptor(vs_storage_op_ctx_t *ctx) {
    vs_firmware_descriptor_t desc;
    BOOL_CHECK_RET(VS_STORAGE_OK ==
                           vs_firmware_save_firmware_descriptor(ctx, (vs_firmware_descriptor_t *)&_test_descriptor),
                   "Error save descriptor");
    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_load_firmware_descriptor(ctx,
                                                                       (uint8_t *)_test_descriptor.info.manufacture_id,
                                                                       (uint8_t *)_test_descriptor.info.device_type,
                                                                       &desc),
                   "Error load descriptor");
    MEMCMP_CHECK_RET(&desc, &_test_descriptor, sizeof(vs_firmware_descriptor_t), false);

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_delete_firmware(ctx, &desc), "Error delete descriptor");
    BOOL_CHECK_RET(VS_STORAGE_ERROR_NOT_FOUND ==
                           vs_firmware_load_firmware_descriptor(ctx,
                                                              (uint8_t *)_test_descriptor.info.manufacture_id,
                                                              (uint8_t *)_test_descriptor.info.device_type,
                                                              &desc),
                   "Error delete descriptor");

    return true;
}

/**********************************************************/
static bool
_test_firmware_save_load_data(vs_storage_op_ctx_t *ctx) {
    uint8_t buf[sizeof(VS_TEST_FIRMWARE_DATA)];
    size_t _sz;
    int key_len = vs_hsm_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    int sign_len = vs_hsm_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    uint16_t footer_sz =
            sizeof(vs_firmware_footer_t) + VS_FW_SIGNATURES_QTY * (sizeof(vs_sign_t) + key_len + sign_len);
    uint8_t footer_buf[footer_sz];

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_save_firmware_descriptor(ctx, &_test_descriptor), "Error save descriptor");

    BOOL_CHECK_RET(
            VS_STORAGE_OK ==
                    vs_firmware_save_firmware_chunk(
                            ctx, &_test_descriptor, (uint8_t *)VS_TEST_FIRMWARE_DATA, sizeof(VS_TEST_FIRMWARE_DATA), 0),
            "Error save data");
    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_load_firmware_chunk(ctx, &_test_descriptor, 0, buf, sizeof(buf), &_sz),
                   "Error read data");
    BOOL_CHECK_RET(_sz == sizeof(VS_TEST_FIRMWARE_DATA), "Error size of reading data");
    MEMCMP_CHECK_RET(buf, VS_TEST_FIRMWARE_DATA, sizeof(VS_TEST_FIRMWARE_DATA), false);

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_save_firmware_footer(ctx, &_test_descriptor, _fw_footer),
                   "Error save footer");
    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_load_firmware_footer(ctx, &_test_descriptor, footer_buf, footer_sz, &_sz),
                   "Error read footer");
    BOOL_CHECK_RET(_sz == footer_sz, "Error size of reading footer");
    MEMCMP_CHECK_RET(footer_buf, _fw_footer, footer_sz, false);

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_verify_firmware(ctx, &_test_descriptor), "Error verify firmware");

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_install_firmware(ctx, &_test_descriptor), "Error install firmware");

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_firmware_delete_firmware(ctx, &_test_descriptor), "Error delete firmware");

    BOOL_CHECK_RET(VS_STORAGE_OK != vs_firmware_install_firmware(ctx, &_test_descriptor),
                   "The install firmware function has returned OK but image has already been deleted");

    return true;
}

/**********************************************************/
uint16_t
vs_firmware_test(vs_storage_op_ctx_t *ctx) {
    uint16_t failed_test_result = 0;

    START_TEST("Update tests");

    TEST_CASE_OK("Prepare test",
                 vs_test_erase_otp_provision() && vs_test_create_device_key() && _create_test_hl_keys() &&
                         _create_test_firmware_footer());
    TEST_CASE_OK("Save load firmware descriptor", _test_firmware_save_load_descriptor(ctx));
    TEST_CASE_OK("Save load firmware data", _test_firmware_save_load_data(ctx));

    if (VS_STORAGE_OK != vs_firmware_init(ctx)) {
        RESULT_ERROR;
    }

terminate:
    if (_fw_footer) {
        VS_IOT_FREE(_fw_footer);
    }

    vs_firnware_deinit(ctx);
    return failed_test_result;
}