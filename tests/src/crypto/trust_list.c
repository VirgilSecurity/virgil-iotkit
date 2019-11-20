#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <virgil/iot/tests/tests.h>
#include <virgil/iot/tests/helpers.h>

#include <stdlib-config.h>
#include <endian-config.h>
#include <trust_list-config.h>
#include <global-hal.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

#include <private/test_hl_keys_data.h>
#include <private/test_tl_data.h>

typedef struct {
    const uint8_t *key;
    uint16_t size;
} test_tl_keys_info_t;

static const vs_tl_header_t *test_header = NULL;
static uint16_t test_header_sz;

static test_tl_keys_info_t *test_tl_keys = NULL;
static uint16_t test_key_max_size = 0;
static const vs_tl_footer_t *test_footer = NULL;
static uint16_t test_footer_sz;

#define BOOL_CHECK_RET_LOGLEV_RESTORE(CONDITION)                                                                       \
    if (!(CONDITION)) {                                                                                                \
        VS_LOG_SET_LOGLEVEL(prev_loglevel);                                                                            \
        return false;                                                                                                  \
    }

/******************************************************************************/
static bool
_parse_test_tl_data(const uint8_t *data, uint16_t size) {
    int sign_len;
    int key_len;
    uint16_t i;
    vs_sign_t *element;
    test_footer_sz = sizeof(vs_tl_footer_t);
    uint16_t pub_keys_count;
    uint8_t signatures_count;

    test_header = (vs_tl_header_t *)data;
    test_header_sz = sizeof(vs_tl_header_t);

    // Use values in host endian
    pub_keys_count = VS_IOT_NTOHS(test_header->pub_keys_count);
    signatures_count = test_header->signatures_count;

    uint8_t *ptr = (uint8_t *)data + sizeof(vs_tl_header_t);

    test_tl_keys = (test_tl_keys_info_t *)VS_IOT_CALLOC(pub_keys_count, sizeof(test_tl_keys_info_t));

    BOOL_CHECK_RET(NULL != test_tl_keys, "Allocate memory error");

    for (i = 0; i < pub_keys_count; ++i) {
        test_tl_keys[i].key = ptr;
        key_len = vs_secmodule_get_pubkey_len(((vs_pubkey_dated_t *)ptr)->pubkey.ec_type);
        uint16_t key_meta_data_sz = VS_IOT_NTOHS(((vs_pubkey_dated_t *)ptr)->pubkey.meta_data_sz);

        BOOL_CHECK_RET(key_len > 0, "Key parse error");

        test_tl_keys[i].size = key_len + sizeof(vs_pubkey_dated_t) + key_meta_data_sz;
        if (test_key_max_size < test_tl_keys[i].size) {
            test_key_max_size = test_tl_keys[i].size;
        }

        ptr += test_tl_keys[i].size;
    }

    test_footer = (vs_tl_footer_t *)ptr;

    element = (vs_sign_t *)(test_footer->signatures);

    for (i = 0; i < signatures_count; ++i) {
        test_footer_sz += sizeof(vs_sign_t);

        sign_len = vs_secmodule_get_signature_len(element->ec_type);
        key_len = vs_secmodule_get_pubkey_len(element->ec_type);

        BOOL_CHECK_RET((key_len > 0 && sign_len > 0), "Footer parse error");

        test_footer_sz += key_len + sign_len;

        element = (vs_sign_t *)((uint8_t *)element + sizeof(vs_sign_t) + key_len + sign_len);
    }

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

/******************************************************************************/
static vs_status_e
_load_tl_part(vs_tl_element_e el, uint16_t index, uint8_t *data, uint16_t size, uint16_t *readed_bytes) {
    vs_tl_element_info_t info;
    info.id = el;
    info.index = index;

    return vs_tl_load_part(&info, data, size, readed_bytes);
}

/******************************************************************************/
static bool
_verify_hl_key(const char *id_str, const uint8_t *in_data, uint16_t data_sz) {

    BOOL_CHECK_RET(VS_CODE_OK == vs_provision_verify_hl_key(in_data, data_sz), "Error verify key %s", id_str);

    return true;
}

/******************************************************************************/
static bool
_test_verify_hl_keys(void) {
    bool res = true;

    res &= _verify_hl_key("PBR1", recovery1_pub, recovery1_pub_len);
    res &= _verify_hl_key("PBR2", recovery2_pub, recovery2_pub_len);

    res &= _verify_hl_key("PBA1", auth1_pub, auth1_pub_len);
    res &= _verify_hl_key("PBA2", auth2_pub, auth2_pub_len);

    res &= _verify_hl_key("PBF1", firmware1_pub, firmware1_pub_len);
    res &= _verify_hl_key("PBF2", firmware2_pub, firmware2_pub_len);

    res &= _verify_hl_key("PBT1", tl_service1_pub, tl_service1_pub_len);
    res &= _verify_hl_key("PBT2", tl_service2_pub, tl_service2_pub_len);

    return res;
}

/******************************************************************************/
static bool
_test_tl_header_save_pass() {

    STATUS_CHECK_RET_BOOL(_save_tl_part(VS_TL_ELEMENT_TLH, 0, (uint8_t *)test_header, test_header_sz),
                          "Error write tl header");
    return true;
}

/******************************************************************************/
static bool
_test_tl_header_read_pass() {
    uint8_t readed_header[test_header_sz];
    uint16_t readed_bytes;

    BOOL_CHECK_RET(
            VS_CODE_OK == _load_tl_part(VS_TL_ELEMENT_TLH, 0, readed_header, sizeof(readed_header), &readed_bytes) &&
                    readed_bytes == test_header_sz,
            "Error read tl header, read %lu bytes, buffer %lu bytes",
            readed_bytes,
            test_header_sz);

    MEMCMP_CHECK_RET(test_header, readed_header, sizeof(readed_header), false);

    return true;
}

/******************************************************************************/
static bool
_test_tl_keys_save_pass() {
    uint16_t i;
    uint16_t pub_keys_count;

    pub_keys_count = VS_IOT_NTOHS(test_header->pub_keys_count);

    for (i = 0; i < pub_keys_count; ++i) {
        BOOL_CHECK_RET(VS_CODE_OK == _save_tl_part(VS_TL_ELEMENT_TLC, i, test_tl_keys[i].key, test_tl_keys[i].size),
                       "Error write tl key %u",
                       i);
    }
    return true;
}

/******************************************************************************/
static bool
_tl_keys_save_wrong_order() {
    uint16_t i;
    uint16_t pub_keys_count;

    pub_keys_count = VS_IOT_NTOHS(test_header->pub_keys_count);

    if (pub_keys_count > 2) {
        for (i = 0; i < pub_keys_count - 2; ++i) {
            BOOL_CHECK_RET(VS_CODE_OK == _save_tl_part(VS_TL_ELEMENT_TLC, i, test_tl_keys[i].key, test_tl_keys[i].size),
                           "Error write tl key %u",
                           i);
        }
    }
    i = pub_keys_count - 1;
    BOOL_CHECK_RET(VS_CODE_OK == _save_tl_part(VS_TL_ELEMENT_TLC, i, test_tl_keys[i].key, test_tl_keys[i].size),
                   "Error write tl key %u",
                   i);
    i = pub_keys_count - 2;
    BOOL_CHECK_RET(VS_CODE_OK == _save_tl_part(VS_TL_ELEMENT_TLC, i, test_tl_keys[i].key, test_tl_keys[i].size),
                   "Error write tl key %u",
                   i);
    return true;
}

/******************************************************************************/
static bool
_test_tl_keys_read_pass() {
    size_t i;
    uint8_t readed_key[VS_TL_STORAGE_MAX_PART_SIZE];
    uint16_t readed_bytes;
    uint16_t pub_keys_count;

    pub_keys_count = VS_IOT_NTOHS(test_header->pub_keys_count);

    for (i = 0; i < pub_keys_count; ++i) {

        BOOL_CHECK_RET(
                VS_CODE_OK == _load_tl_part(VS_TL_ELEMENT_TLC, i, readed_key, sizeof(readed_key), &readed_bytes) &&
                        test_tl_keys[i].size == readed_bytes,
                "Error read tl key %lu, read %lu bytes",
                i,
                readed_bytes);

        MEMCMP_CHECK_RET(test_tl_keys[i].key, &readed_key, test_tl_keys[i].size, false);
    }

    return true;
}

/******************************************************************************/
static bool
_test_tl_footer_save_pass() {

    BOOL_CHECK_RET(VS_CODE_OK == _save_tl_part(VS_TL_ELEMENT_TLF, 0, (uint8_t *)test_footer, test_footer_sz),
                   "Error write tl footer");

    return true;
}

/******************************************************************************/
static bool
_test_tl_footer_read_pass() {

    uint8_t readed_footer[test_footer_sz];
    uint16_t readed_bytes;

    BOOL_CHECK_RET(VS_CODE_OK == _load_tl_part(VS_TL_ELEMENT_TLF, 0, readed_footer, test_footer_sz, &readed_bytes) &&
                           readed_bytes == test_footer_sz,
                   "Error read tl footer, read %lu bytes, buffer %lu bytes",
                   readed_bytes,
                   test_footer_sz);

    MEMCMP_CHECK_RET(test_footer, &readed_footer, test_footer_sz, false);

    return true;
}

/******************************************************************************/
static bool
_test_tl_save_pass() {
    return _test_tl_header_save_pass() && _test_tl_keys_save_pass() && _test_tl_footer_save_pass();
}

/******************************************************************************/
static bool
_test_tl_save_header_fail() {
    vs_tl_header_t header;
    bool res;
    vs_log_level_t prev_loglevel = VS_LOG_SET_LOGLEVEL(VS_LOGLEV_ALERT);

    VS_IOT_MEMCPY(&header, test_header, test_header_sz);

    VS_HEADER_SUBCASE("tl has big size");
    header.tl_size = VS_TL_STORAGE_SIZE + 1;
    res = (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLH, 0, (uint8_t *)&header, test_header_sz));
    header.tl_size = test_header->tl_size;
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("tl header has wrong size");
    res = (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLH, 0, (uint8_t *)&header, test_header_sz - 1));
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_LOG_SET_LOGLEVEL(prev_loglevel);
    return true;
}

/******************************************************************************/
static bool
_test_tl_save_keys_fail() {
    uint8_t key[test_key_max_size];
    vs_pubkey_dated_t *key_info = (vs_pubkey_dated_t *)key;
    vs_pubkey_dated_t *ref_key_info = (vs_pubkey_dated_t *)test_tl_keys[0].key;
    vs_log_level_t prev_loglevel = VS_LOG_SET_LOGLEVEL(VS_LOGLEV_ALERT);
    bool res;

    VS_IOT_MEMCPY(key, test_tl_keys[0].key, test_tl_keys[0].size);

    VS_HEADER_SUBCASE("tl keys more than necessary");
    res = _test_tl_header_save_pass() && _test_tl_keys_save_pass();
    res &= (VS_CODE_OK !=
            _save_tl_part(VS_TL_ELEMENT_TLC, test_header->pub_keys_count, test_tl_keys[0].key, test_tl_keys[0].size));
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);


    VS_HEADER_SUBCASE("tl key has wrong size");
    res = _test_tl_header_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLC, 0, test_tl_keys[0].key, test_tl_keys[0].size - 1));
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("tl key has wrong ec_type");
    key_info->pubkey.ec_type = 0xFF;
    res = _test_tl_header_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLC, 0, key, test_tl_keys[0].size));
    key_info->pubkey.ec_type = ref_key_info->pubkey.ec_type;
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("tl key has wrong key_type");
    key_info->pubkey.key_type = 0xFF;
    res = _test_tl_header_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLC, 0, key, test_tl_keys[0].size));
    key_info->pubkey.key_type = ref_key_info->pubkey.key_type;
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_LOG_SET_LOGLEVEL(prev_loglevel);
    return res;
}

/******************************************************************************/
static bool
_test_tl_save_footer_fail() {
    uint8_t footer[test_footer_sz];
    vs_tl_footer_t *footer_info = (vs_tl_footer_t *)footer;
    vs_sign_t *sign = (vs_sign_t *)footer_info->signatures;
    vs_sign_t *ref_sign = (vs_sign_t *)test_footer->signatures;
    int sign_len;

    bool res;
    vs_log_level_t prev_loglevel = VS_LOG_SET_LOGLEVEL(VS_LOGLEV_ALERT);

    VS_IOT_MEMCPY(footer, test_footer, test_footer_sz);

    VS_HEADER_SUBCASE("footer has wrong size");
    res = _test_tl_header_save_pass() && _test_tl_keys_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLF, 0, (uint8_t *)test_footer, test_footer_sz - 1));
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("footer signature has wrong ec_type");
    sign->ec_type = 0xFF;
    res = _test_tl_header_save_pass() && _test_tl_keys_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLF, 0, footer, test_footer_sz));
    sign->ec_type = ref_sign->ec_type;
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("footer signature has wrong signer_type");
    sign->signer_type = 0xFF;
    res = _test_tl_header_save_pass() && _test_tl_keys_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLF, 0, footer, test_footer_sz));
    sign->signer_type = ref_sign->signer_type;
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("footer signature has wrong hash_type");
    sign->hash_type = 0xFF;
    res = _test_tl_header_save_pass() && _test_tl_keys_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLF, 0, footer, test_footer_sz));
    sign->hash_type = ref_sign->hash_type;
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("footer signature has wrong signature");
    sign->raw_sign_pubkey[0] = ~sign->raw_sign_pubkey[0];
    res = _test_tl_header_save_pass() && _test_tl_keys_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLF, 0, footer, test_footer_sz));
    sign->raw_sign_pubkey[0] = ref_sign->raw_sign_pubkey[0];
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("footer signature has wrong signer public key");
    sign_len = vs_secmodule_get_signature_len(sign->ec_type);
    sign->raw_sign_pubkey[sign_len] = ~sign->raw_sign_pubkey[sign_len];
    res = _test_tl_header_save_pass() && _test_tl_keys_save_pass();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLF, 0, footer, test_footer_sz));
    sign->raw_sign_pubkey[sign_len] = ref_sign->raw_sign_pubkey[sign_len];
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("Wrong tl body");
    res = _test_tl_header_save_pass() && _tl_keys_save_wrong_order();
    res &= (VS_CODE_OK != _save_tl_part(VS_TL_ELEMENT_TLF, 0, footer, test_footer_sz));
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_HEADER_SUBCASE("Check success save");
    res = _test_tl_save_pass();
    BOOL_CHECK_RET_LOGLEV_RESTORE(res);

    VS_LOG_SET_LOGLEVEL(prev_loglevel);
    return res;
}

/******************************************************************************/
static bool
_test_tl_read_pass() {
    return _test_tl_header_read_pass() && _test_tl_keys_read_pass() && _test_tl_footer_read_pass();
}

/******************************************************************************/
uint16_t
test_keystorage_and_tl(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;

    START_TEST("Provision and TL tests");

    if (!_parse_test_tl_data(tl_data1, tl_data1_len)) {
        VS_LOG_ERROR("Bad test data");
        RESULT_ERROR;
    }

    TEST_CASE_OK("Erase otp provision", vs_test_erase_otp_provision(secmodule_impl));
    TEST_CASE_OK("TL save hl keys", vs_test_save_hl_pubkeys(secmodule_impl));
    TEST_CASE_OK("TL verify hl keys", _test_verify_hl_keys());

    TEST_CASE_OK("TL save", _test_tl_save_pass());
    TEST_CASE_OK("TL read", _test_tl_read_pass());

    TEST_CASE_OK("TL header save fail", _test_tl_save_header_fail());
    TEST_CASE_OK("TL keys save fail", _test_tl_save_keys_fail());

    TEST_CASE_OK("TL save footer fail", _test_tl_save_footer_fail());

terminate:

    VS_IOT_FREE(test_tl_keys);
    return failed_test_result;
}
