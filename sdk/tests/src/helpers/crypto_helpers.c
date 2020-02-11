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

#include <stdlib-config.h>
#include <stdbool.h>
#include <stdlib.h>
#include <virgil/iot/tests/helpers.h>
#include <private/test_hl_keys_data.h>

#include <trust_list-config.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/trust_list/trust_list.h>

/******************************************************************************/
static bool
_save_hl_key(vs_secmodule_impl_t *secmodule_impl,
             size_t slot,
             const char *id_str,
             const uint8_t *in_data,
             uint16_t data_sz) {

    STATUS_CHECK_RET_BOOL(
            secmodule_impl->slot_save(slot, in_data, data_sz), "Unable to save data to slot = %d (%s)", slot, id_str);

    return true;
}

/**********************************************************/
static bool
_create_test_signed_hl_key(vs_secmodule_impl_t *secmodule_impl,
                           vs_key_type_e hl_key_type,
                           vs_iot_secmodule_slot_e slot_with_hl_keypair,
                           vs_iot_secmodule_slot_e slot_to_save_pubkey,
                           bool with_signature) {
    uint8_t buf[PUBKEY_MAX_BUF_SIZE];
    uint8_t hash_buf[32];
    int key_len = vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    int sign_len = vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    uint16_t hl_slot_sz = sizeof(vs_pubkey_dated_t) + key_len + sizeof(vs_sign_t) + sign_len + key_len;
    vs_pubkey_dated_t *hl_key = (vs_pubkey_dated_t *)buf;
    vs_secmodule_keypair_type_e pubkey_type;
    uint16_t _sz;

    VS_IOT_MEMSET(buf, 0, sizeof(buf));
    hl_key->start_date = 0;
    hl_key->expire_date = UINT32_MAX;
    hl_key->pubkey.ec_type = VS_KEYPAIR_EC_SECP256R1;
    hl_key->pubkey.key_type = hl_key_type;
    hl_key->pubkey.meta_data_sz = 0;

    BOOL_CHECK_RET(VS_CODE_OK ==
                           secmodule_impl->get_pubkey(
                                   slot_with_hl_keypair, hl_key->pubkey.meta_and_pubkey, key_len, &_sz, &pubkey_type),
                   "Error get test pubkey");

    if (with_signature) {
        STATUS_CHECK_RET_BOOL(
                secmodule_impl->hash(
                        VS_HASH_SHA_256, buf, sizeof(vs_pubkey_dated_t) + key_len, hash_buf, sizeof(hash_buf), &_sz),
                "ERROR while creating hash for test key");

        vs_sign_t *sign = (vs_sign_t *)(hl_key->pubkey.meta_and_pubkey + key_len);
        sign->signer_type = VS_KEY_RECOVERY;
        sign->hash_type = VS_HASH_SHA_256;
        sign->ec_type = VS_KEYPAIR_EC_SECP256R1;

        BOOL_CHECK_RET(
                VS_CODE_OK ==
                        secmodule_impl->ecdsa_sign(
                                TEST_REC_KEYPAIR, VS_HASH_SHA_256, hash_buf, sign->raw_sign_pubkey, sign_len, &_sz),
                "Error sign test pubkey");

        BOOL_CHECK_RET(VS_CODE_OK ==
                               secmodule_impl->get_pubkey(
                                       TEST_REC_KEYPAIR, sign->raw_sign_pubkey + sign_len, key_len, &_sz, &pubkey_type),
                       "Error get test RECOVERY pubkey");
    }
    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->slot_save(slot_to_save_pubkey, buf, hl_slot_sz),
                   "Error save test pubkey");
    return true;
}

/**********************************************************/
bool
vs_test_erase_otp_provision(vs_secmodule_impl_t *secmodule_impl) {
    VS_HEADER_SUBCASE("Erase otp slots");
    if (VS_CODE_OK != secmodule_impl->slot_clean(PRIVATE_KEY_SLOT) ||
        VS_CODE_OK != secmodule_impl->slot_clean(REC1_KEY_SLOT) ||
        VS_CODE_OK != secmodule_impl->slot_clean(REC2_KEY_SLOT) ||
        VS_CODE_OK != secmodule_impl->slot_clean(SIGNATURE_SLOT)) {
        VS_LOG_ERROR("[AP] Error. Can't erase OTP slots. ");
        return false;
    }
    return true;
}

/**********************************************************/
bool
vs_test_create_device_key(vs_secmodule_impl_t *secmodule_impl) {
    VS_HEADER_SUBCASE("Create device keypair");
    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->create_keypair(PRIVATE_KEY_SLOT, VS_KEYPAIR_EC_SECP256R1),
                   "Error create device key");
    return true;
}

/**********************************************************/
bool
vs_test_save_hl_pubkeys(vs_secmodule_impl_t *secmodule_impl) {
    bool res = true;
    res &= _save_hl_key(secmodule_impl, REC1_KEY_SLOT, "PBR1", recovery1_pub, recovery1_pub_len);
    res &= _save_hl_key(secmodule_impl, REC2_KEY_SLOT, "PBR2", recovery2_pub, recovery2_pub_len);

    res &= _save_hl_key(secmodule_impl, AUTH1_KEY_SLOT, "PBA1", auth1_pub, auth1_pub_len);
    res &= _save_hl_key(secmodule_impl, AUTH2_KEY_SLOT, "PBA2", auth2_pub, auth2_pub_len);

    res &= _save_hl_key(secmodule_impl, FW1_KEY_SLOT, "PBF1", firmware1_pub, firmware1_pub_len);
    res &= _save_hl_key(secmodule_impl, FW2_KEY_SLOT, "PBF2", firmware2_pub, firmware2_pub_len);

    res &= _save_hl_key(secmodule_impl, TL1_KEY_SLOT, "PBT1", tl_service1_pub, tl_service1_pub_len);
    res &= _save_hl_key(secmodule_impl, TL2_KEY_SLOT, "PBT2", tl_service2_pub, tl_service2_pub_len);

    return res;
}

/**********************************************************/
bool
vs_test_create_test_hl_keys(vs_secmodule_impl_t *secmodule_impl) {
    VS_HEADER_SUBCASE("Create test hl keys");
    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->create_keypair(TEST_REC_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test recovery keypair");
    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->create_keypair(TEST_AUTH_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test auth keypair");
    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->create_keypair(TEST_FW_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test FW keypair");
    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->create_keypair(TEST_TL_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test TL keypair");

    BOOL_CHECK_RET(_create_test_signed_hl_key(secmodule_impl, VS_KEY_RECOVERY, TEST_REC_KEYPAIR, REC1_KEY_SLOT, false),
                   "Error while creating signed test rec key");
    BOOL_CHECK_RET(_create_test_signed_hl_key(secmodule_impl, VS_KEY_AUTH, TEST_AUTH_KEYPAIR, AUTH1_KEY_SLOT, true),
                   "Error while creating signed test auth key");
    BOOL_CHECK_RET(_create_test_signed_hl_key(secmodule_impl, VS_KEY_FIRMWARE, TEST_FW_KEYPAIR, FW1_KEY_SLOT, true),
                   "Error while creating signed test FW key");
    BOOL_CHECK_RET(_create_test_signed_hl_key(secmodule_impl, VS_KEY_TRUSTLIST, TEST_TL_KEYPAIR, TL1_KEY_SLOT, true),
                   "Error while creating signed test TL key");

    return true;
}

/******************************************************************************/
static vs_status_e
_save_tl_part(vs_tl_element_e el, uint16_t index, const uint8_t *data, uint16_t size) {
    vs_tl_element_info_t info;
    info.id = el;
    info.index = index;

    return vs_tl_save_part(&info, data, size);
}

/**********************************************************/
bool
vs_test_create_test_tl(vs_secmodule_impl_t *secmodule_impl) {
    const vs_key_type_e signer_key_type_list[VS_TL_SIGNATURES_QTY] = VS_TL_SIGNER_TYPE_LIST;
    const vs_iot_secmodule_slot_e signer_key_slots_list[VS_TL_SIGNATURES_QTY] = {TEST_AUTH_KEYPAIR, TEST_TL_KEYPAIR};

    vs_tl_header_t test_header = {
            .version.major = 0,
            .version.minor = 0,
            .version.patch = 0,
            .version.build = 0,
            .version.timestamp = 0,
            .signatures_count = VS_TL_SIGNATURES_QTY,
            .pub_keys_count = 1,
    };
    vs_tl_header_t net_header;
    uint16_t key_len = (uint16_t)vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    uint16_t sign_len = (uint16_t)vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);

    uint8_t hash_buf[SHA256_SIZE];
    vs_secmodule_sw_sha256_ctx ctx;
    secmodule_impl->hash_init(&ctx);

    uint16_t footer_sz = sizeof(vs_tl_footer_t) + VS_TL_SIGNATURES_QTY * (sizeof(vs_sign_t) + key_len + sign_len);
    uint16_t key_el_sz = sizeof(vs_pubkey_dated_t) + key_len;
    test_header.tl_size = sizeof(vs_tl_header_t) + key_el_sz + footer_sz;

    uint8_t buf[key_el_sz > footer_sz ? key_el_sz : footer_sz];
    vs_pubkey_dated_t *key_el = (vs_pubkey_dated_t *)buf;
    VS_IOT_MEMSET(buf, 0, sizeof(buf));

    uint16_t _sz;
    vs_secmodule_keypair_type_e pubkey_type;

    key_el->start_date = 0;
    key_el->expire_date = UINT32_MAX;
    key_el->pubkey.ec_type = VS_KEYPAIR_EC_SECP256R1;
    key_el->pubkey.key_type = VS_KEY_FACTORY;
    key_el->pubkey.meta_data_sz = 0;


    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->create_keypair(TEST_USER_KEYPAIR, VS_KEYPAIR_EC_SECP256R1),
                   "Error create test recovery keypair");

    BOOL_CHECK_RET(VS_CODE_OK ==
                           secmodule_impl->get_pubkey(
                                   TEST_USER_KEYPAIR, key_el->pubkey.meta_and_pubkey, key_len, &_sz, &pubkey_type),
                   "Error get test pubkey");

    vs_tl_header_to_net(&test_header, &net_header);
    secmodule_impl->hash_update(&ctx, (uint8_t *)&net_header, sizeof(vs_tl_header_t));

    BOOL_CHECK_RET(VS_CODE_OK == _save_tl_part(VS_TL_ELEMENT_TLH, 0, (uint8_t *)&net_header, sizeof(vs_tl_header_t)),
                   "Error write tl header");

    secmodule_impl->hash_update(&ctx, buf, key_el_sz);
    BOOL_CHECK_RET(VS_CODE_OK == _save_tl_part(VS_TL_ELEMENT_TLC, 0, buf, key_el_sz), "Error write tl key");

    uint16_t i;

    vs_tl_footer_t *footer = (vs_tl_footer_t *)buf;
    footer->tl_type = 0;
    secmodule_impl->hash_update(&ctx, (uint8_t *)&footer->tl_type, sizeof(footer->tl_type));
    secmodule_impl->hash_finish(&ctx, hash_buf);

    vs_sign_t *sign = (vs_sign_t *)(footer->signatures);

    for (i = 0; i < VS_TL_SIGNATURES_QTY; ++i) {
        uint8_t signer_key[key_len];

        sign->signer_type = signer_key_type_list[i];
        sign->hash_type = VS_HASH_SHA_256;
        sign->ec_type = VS_KEYPAIR_EC_SECP256R1;

        BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->get_pubkey(
                                             signer_key_slots_list[i], signer_key, key_len, &_sz, &pubkey_type),
                       "Error get test pubkey");

        BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->ecdsa_sign(signer_key_slots_list[i],
                                                                VS_HASH_SHA_256,
                                                                hash_buf,
                                                                sign->raw_sign_pubkey,
                                                                sign_len,
                                                                &_sz),
                       "Error sign test pubkey");
        VS_IOT_MEMCPY(sign->raw_sign_pubkey + sign_len, signer_key, key_len);

        sign = (vs_sign_t *)((uint8_t *)sign + sizeof(vs_sign_t) + key_len + sign_len);
    }

    BOOL_CHECK_RET(VS_CODE_OK == _save_tl_part(VS_TL_ELEMENT_TLF, 0, buf, footer_sz), "Error write tl footer");

    return true;
}

/******************************************************************************/
const char *
vs_test_secmodule_slot_descr(vs_iot_secmodule_slot_e slot) {
    switch (slot) {
    case VS_KEY_SLOT_STD_OTP_0:
        return "STD_OTP_0";
    case VS_KEY_SLOT_STD_OTP_1:
        return "STD_OTP_1";
    case VS_KEY_SLOT_STD_OTP_2:
        return "STD_OTP_2";
    case VS_KEY_SLOT_STD_OTP_3:
        return "STD_OTP_3";
    case VS_KEY_SLOT_STD_OTP_4:
        return "STD_OTP_4";
    case VS_KEY_SLOT_STD_OTP_5:
        return "STD_OTP_5";
    case VS_KEY_SLOT_STD_OTP_6:
        return "STD_OTP_6";
    case VS_KEY_SLOT_STD_OTP_7:
        return "STD_OTP_7";
    case VS_KEY_SLOT_STD_OTP_8:
        return "STD_OTP_8";
    case VS_KEY_SLOT_STD_OTP_9:
        return "STD_OTP_9";
    case VS_KEY_SLOT_STD_OTP_10:
        return "STD_OTP_10";
    case VS_KEY_SLOT_STD_OTP_11:
        return "STD_OTP_11";
    case VS_KEY_SLOT_STD_OTP_12:
        return "STD_OTP_12";
    case VS_KEY_SLOT_STD_OTP_13:
        return "STD_OTP_13";
    case VS_KEY_SLOT_STD_OTP_14:
        return "STD_OTP_14";
    case VS_KEY_SLOT_EXT_OTP_0:
        return "EXT_OTP_0";
    case VS_KEY_SLOT_STD_MTP_0:
        return "STD_MTP_0";
    case VS_KEY_SLOT_STD_MTP_1:
        return "STD_MTP_1";
    case VS_KEY_SLOT_STD_MTP_2:
        return "STD_MTP_2";
    case VS_KEY_SLOT_STD_MTP_3:
        return "STD_MTP_3";
    case VS_KEY_SLOT_STD_MTP_4:
        return "STD_MTP_4";
    case VS_KEY_SLOT_STD_MTP_5:
        return "STD_MTP_5";
    case VS_KEY_SLOT_STD_MTP_6:
        return "STD_MTP_6";
    case VS_KEY_SLOT_STD_MTP_7:
        return "STD_MTP_7";
    case VS_KEY_SLOT_STD_MTP_8:
        return "STD_MTP_8";
    case VS_KEY_SLOT_STD_MTP_9:
        return "STD_MTP_9";
    case VS_KEY_SLOT_STD_MTP_10:
        return "STD_MTP_10";
    case VS_KEY_SLOT_STD_MTP_11:
        return "STD_MTP_11";
    case VS_KEY_SLOT_STD_MTP_12:
        return "STD_MTP_12";
    case VS_KEY_SLOT_STD_MTP_13:
        return "STD_MTP_13";
    case VS_KEY_SLOT_STD_MTP_14:
        return "STD_MTP_14";
    case VS_KEY_SLOT_EXT_MTP_0:
        return "EXT_MTP_0";
    case VS_KEY_SLOT_STD_TMP_0:
        return "STD_TMP_0";
    case VS_KEY_SLOT_STD_TMP_1:
        return "STD_TMP_1";
    case VS_KEY_SLOT_STD_TMP_2:
        return "STD_TMP_2";
    case VS_KEY_SLOT_STD_TMP_3:
        return "STD_TMP_3";
    case VS_KEY_SLOT_STD_TMP_4:
        return "STD_TMP_4";
    case VS_KEY_SLOT_STD_TMP_5:
        return "STD_TMP_5";
    case VS_KEY_SLOT_STD_TMP_6:
        return "STD_TMP_6";
    case VS_KEY_SLOT_EXT_TMP_0:
        return "EXT_TMP_0";
    default:
        VS_IOT_ASSERT(false && "Unsupported slot");
        return "";
    }
}
