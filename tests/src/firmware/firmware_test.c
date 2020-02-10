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

#include <stdlib.h>

#include <global-hal.h>
#include <update-config.h>
#include <virgil/iot/tests/tests.h>
#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/macros/macros.h>

#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/provision/provision.h>

#define VS_TEST_FIRMWARE_DATA "test firmware data for verifying update library"
#define VS_TEST_FILL_SIZE 256

static uint8_t *_fw_footer = NULL;

static vs_firmware_descriptor_t _test_descriptor = {
        .info.manufacture_id = TEST_MANUFACTURE_ID,
        .info.device_type = TEST_DEVICE_TYPE,
        .info.version.major = 0,
        .info.version.minor = 1,
        .info.version.patch = 3,
        .info.version.build = 0,
        .info.version.timestamp = 0,
        .padding = 0,
        .chunk_size = 256,
        .firmware_length = sizeof(VS_TEST_FIRMWARE_DATA),
        .app_size = sizeof(VS_TEST_FIRMWARE_DATA) + VS_TEST_FILL_SIZE,
};

/**********************************************************/
static bool
_create_test_firmware_signature(vs_secmodule_impl_t *secmodule_impl,
                                vs_key_type_e signer_type,
                                vs_iot_secmodule_slot_e slot_with_hl_keypair,
                                uint8_t fw_hash[32],
                                vs_sign_t *sign_buf) {
    int sign_len = vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    int key_len = vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    uint16_t _sz;
    vs_secmodule_keypair_type_e pubkey_type;

    sign_buf->signer_type = signer_type;
    sign_buf->ec_type = VS_KEYPAIR_EC_SECP256R1;
    sign_buf->hash_type = VS_HASH_SHA_256;

    BOOL_CHECK_RET(
            VS_CODE_OK ==
                    secmodule_impl->ecdsa_sign(
                            slot_with_hl_keypair, VS_HASH_SHA_256, fw_hash, sign_buf->raw_sign_pubkey, sign_len, &_sz),
            "Error sign test firmware by auth key");
    BOOL_CHECK_RET(
            VS_CODE_OK ==
                    secmodule_impl->get_pubkey(
                            slot_with_hl_keypair, sign_buf->raw_sign_pubkey + sign_len, key_len, &_sz, &pubkey_type),
            "Error get test aut pubkey");
    return true;
}

/**********************************************************/
static bool
_create_test_firmware_footer(vs_secmodule_impl_t *secmodule_impl, vs_firmware_descriptor_t *desc) {
    vs_firmware_footer_t *footer;
    int key_len = vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    int sign_len = vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);

    uint8_t fill[VS_TEST_FILL_SIZE];
    VS_IOT_MEMSET(fill, 0xFF, sizeof(fill));

    VS_HEADER_SUBCASE("Create test firmware footer");
    uint16_t footer_sz = sizeof(vs_firmware_footer_t) + VS_FW_SIGNATURES_QTY * (sizeof(vs_sign_t) + key_len + sign_len);

    if (_fw_footer) {
        VS_IOT_FREE(_fw_footer);
    }

    _fw_footer = VS_IOT_MALLOC(footer_sz);
    desc->app_size += footer_sz;
    if (NULL == _fw_footer) {
        VS_LOG_ERROR("Error while memory alloc");
        return false;
    }

    footer = (vs_firmware_footer_t *)_fw_footer;

    vs_secmodule_sw_sha256_ctx hash_ctx;
    uint8_t hash[32];
    secmodule_impl->hash_init(&hash_ctx);

    footer->signatures_count = VS_FW_SIGNATURES_QTY;
    VS_IOT_MEMCPY(&footer->descriptor, desc, sizeof(vs_firmware_descriptor_t));

    secmodule_impl->hash_update(&hash_ctx, (uint8_t *)VS_TEST_FIRMWARE_DATA, sizeof(VS_TEST_FIRMWARE_DATA));
    secmodule_impl->hash_update(&hash_ctx, fill, sizeof(fill));
    secmodule_impl->hash_update(&hash_ctx, _fw_footer, sizeof(vs_firmware_footer_t));
    secmodule_impl->hash_finish(&hash_ctx, hash);

    vs_sign_t *sign = (vs_sign_t *)footer->signatures;

    BOOL_CHECK_RET(_create_test_firmware_signature(secmodule_impl, VS_KEY_AUTH, TEST_AUTH_KEYPAIR, hash, sign),
                   "Error while creating auth signature");

    sign = (vs_sign_t *)(sign->raw_sign_pubkey + sign_len + key_len);

    BOOL_CHECK_RET(_create_test_firmware_signature(secmodule_impl, VS_KEY_FIRMWARE, TEST_FW_KEYPAIR, hash, sign),
                   "Error while creating fw signature");

    return true;
}
/**********************************************************/
static bool
_test_firmware_save_load_descriptor(void) {
    vs_firmware_descriptor_t desc;
    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_save_firmware_descriptor((vs_firmware_descriptor_t *)&_test_descriptor),
                   "Error save descriptor");
    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_load_firmware_descriptor((uint8_t *)_test_descriptor.info.manufacture_id,
                                                                      (uint8_t *)_test_descriptor.info.device_type,
                                                                      &desc),
                   "Error load descriptor");
    MEMCMP_CHECK_RET(&desc, &_test_descriptor, sizeof(vs_firmware_descriptor_t), false);

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_delete_firmware(&desc), "Error delete descriptor");
    BOOL_CHECK_RET(VS_CODE_ERR_NOT_FOUND ==
                           vs_firmware_load_firmware_descriptor((uint8_t *)_test_descriptor.info.manufacture_id,
                                                                (uint8_t *)_test_descriptor.info.device_type,
                                                                &desc),
                   "Error delete descriptor");

    return true;
}

/**********************************************************/
static bool
_test_firmware_save_load_data(void) {
    uint8_t buf[sizeof(VS_TEST_FIRMWARE_DATA)];
    size_t _sz;
    int key_len = vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    int sign_len = vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    uint16_t footer_sz = sizeof(vs_firmware_footer_t) + VS_FW_SIGNATURES_QTY * (sizeof(vs_sign_t) + key_len + sign_len);
    uint8_t footer_buf[footer_sz];

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_save_firmware_descriptor(&_test_descriptor), "Error save descriptor");

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_save_firmware_chunk(&_test_descriptor,
                                                                 (uint8_t *)VS_TEST_FIRMWARE_DATA,
                                                                 sizeof(VS_TEST_FIRMWARE_DATA),
                                                                 0),
                   "Error save data");
    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_load_firmware_chunk(&_test_descriptor, 0, buf, sizeof(buf), &_sz),
                   "Error read data");
    BOOL_CHECK_RET(_sz == sizeof(VS_TEST_FIRMWARE_DATA), "Error size of reading data");
    MEMCMP_CHECK_RET(buf, VS_TEST_FIRMWARE_DATA, sizeof(VS_TEST_FIRMWARE_DATA), false);

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_save_firmware_footer(&_test_descriptor, _fw_footer), "Error save footer");
    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_load_firmware_footer(&_test_descriptor, footer_buf, footer_sz, &_sz),
                   "Error read footer");
    BOOL_CHECK_RET(_sz == footer_sz, "Error size of reading footer");
    MEMCMP_CHECK_RET(footer_buf, _fw_footer, footer_sz, false);

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_verify_firmware(&_test_descriptor), "Error verify firmware");

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_delete_firmware(&_test_descriptor), "Error delete firmware");

    return true;
}

/**********************************************************/
static bool
_test_firmware_install(vs_secmodule_impl_t *secmodule_impl) {

    vs_firmware_descriptor_t new_desc;
    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_get_own_firmware_descriptor(&new_desc), "Error install firmware");

    new_desc.info.version.major++;
    new_desc.info.version.build++;
    new_desc.padding = _test_descriptor.padding;
    new_desc.chunk_size = _test_descriptor.chunk_size;
    new_desc.firmware_length = _test_descriptor.firmware_length;
    new_desc.app_size = _test_descriptor.app_size;

    BOOL_CHECK_RET(_create_test_firmware_footer(secmodule_impl, &new_desc), "Error create firmware footer");

    VS_HEADER_SUBCASE("Store new firmware");
    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_save_firmware_descriptor(&new_desc), "Error save descriptor");

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_save_firmware_chunk(
                                         &new_desc, (uint8_t *)VS_TEST_FIRMWARE_DATA, sizeof(VS_TEST_FIRMWARE_DATA), 0),
                   "Error save data");

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_save_firmware_footer(&new_desc, _fw_footer), "Error save footer");

    VS_HEADER_SUBCASE("Install new firmware");
    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_install_firmware(&new_desc), "Error install firmware");

    BOOL_CHECK_RET(VS_CODE_OK == vs_firmware_delete_firmware(&new_desc), "Error delete firmware");

    BOOL_CHECK_RET(VS_CODE_OK != vs_firmware_install_firmware(&new_desc),
                   "The install firmware function has returned OK but image has already been deleted");
    return true;
}

/**********************************************************/
uint16_t
vs_firmware_test(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;
    VS_IOT_ASSERT(secmodule_impl);

    START_TEST("Update firmware tests");

    TEST_CASE_OK("Prepare test",
                 vs_test_erase_otp_provision(secmodule_impl) && vs_test_create_device_key(secmodule_impl) &&
                         vs_test_create_test_hl_keys(secmodule_impl) &&
                         _create_test_firmware_footer(secmodule_impl, &_test_descriptor));
    TEST_CASE_OK("Save load firmware descriptor", _test_firmware_save_load_descriptor());
    TEST_CASE_OK("Save load firmware data", _test_firmware_save_load_data());
    TEST_CASE_OK("Save install firmware", _test_firmware_install(secmodule_impl));

terminate:
    if (_fw_footer) {
        VS_IOT_FREE(_fw_footer);
    }

    return failed_test_result;
}