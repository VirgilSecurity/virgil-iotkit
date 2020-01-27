#include <virgil/iot/tests/helpers.h>
#include <private/private_helpers.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <stdlib-config.h>

typedef struct {
    vs_iot_secmodule_slot_e slot;
    vs_secmodule_keypair_type_e keypair_type;
    uint8_t buf[PUBKEY_MAX_BUF_SIZE];
    uint16_t key_sz;
    uint16_t expected_size;
    bool initialized;
} _test_case_t;

/******************************************************************************/
static bool
_test_keypair_generate(vs_secmodule_impl_t *secmodule_impl, _test_case_t *test_case) {
    vs_secmodule_keypair_type_e keypair;

    test_case->initialized = true;

    STATUS_CHECK_RET_BOOL(secmodule_impl->create_keypair(test_case->slot, test_case->keypair_type),
                          "vs_secmodule_keypair_create call error");
    STATUS_CHECK_RET_BOOL(
            secmodule_impl->get_pubkey(
                    test_case->slot, test_case->buf, sizeof(test_case->buf), &test_case->key_sz, &keypair),
            "vs_secmodule_keypair_get_pubkey call error");
    BOOL_CHECK_RET(keypair == test_case->keypair_type, "Received key pair type error");
    BOOL_CHECK_RET(test_case->key_sz == test_case->expected_size, "Received buffer error");

    return true;
}

/******************************************************************************/
static bool
_compare_outputs(_test_case_t *test_cases, size_t cases_amount) {

    size_t pos;
    size_t pos2;

    for (pos = 0; pos < cases_amount; ++pos) {
        if (!test_cases[pos].initialized) {
            continue;
        }

        for (pos2 = pos + 1; pos2 < cases_amount; ++pos2) {
            if (!test_cases[pos2].initialized) {
                continue;
            }
            if (test_cases[pos].key_sz != test_cases[pos2].key_sz) {
                continue;
            }

            if (VS_IOT_MEMCMP(test_cases[pos].buf, test_cases[pos2].buf, test_cases[pos].key_sz) == 0) {
                VS_LOG_ERROR(
                        "The same keys are generated for (slot = %d, key type = %s) and (slot = %d, key type = %s)",
                        test_cases[pos].slot,
                        vs_secmodule_keypair_type_descr(test_cases[pos].keypair_type),
                        test_cases[pos2].slot,
                        vs_secmodule_keypair_type_descr(test_cases[pos2].keypair_type));

                return false;
            }
        }
    }

    return true;
}

/******************************************************************************/
uint16_t
test_keypair(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;

    _test_case_t test_cases[] = {
            {.slot = VS_KEY_SLOT_STD_MTP_0, .keypair_type = VS_KEYPAIR_EC_SECP192R1, .expected_size = 49},
            {.slot = VS_KEY_SLOT_STD_MTP_1, .keypair_type = VS_KEYPAIR_EC_SECP224R1, .expected_size = 57},
            {.slot = VS_KEY_SLOT_STD_MTP_2, .keypair_type = VS_KEYPAIR_EC_SECP256R1, .expected_size = 65},
            {.slot = VS_KEY_SLOT_STD_MTP_3, .keypair_type = VS_KEYPAIR_EC_SECP384R1, .expected_size = 97},
            {.slot = VS_KEY_SLOT_EXT_TMP_0, .keypair_type = VS_KEYPAIR_EC_SECP521R1, .expected_size = 133},
            {.slot = VS_KEY_SLOT_STD_MTP_4, .keypair_type = VS_KEYPAIR_EC_SECP192K1, .expected_size = 49},
            {.slot = VS_KEY_SLOT_STD_MTP_5, .keypair_type = VS_KEYPAIR_EC_SECP224K1, .expected_size = 57},
            {.slot = VS_KEY_SLOT_STD_MTP_6, .keypair_type = VS_KEYPAIR_EC_SECP256K1, .expected_size = 65},
            {.slot = VS_KEY_SLOT_STD_MTP_7, .keypair_type = VS_KEYPAIR_EC_CURVE25519, .expected_size = 32},
            {.slot = VS_KEY_SLOT_STD_MTP_8, .keypair_type = VS_KEYPAIR_EC_ED25519, .expected_size = 32}};

    static const size_t cases_amount = sizeof(test_cases) / sizeof(test_cases[0]);
    size_t pos;
    char buf[256];
    bool not_implemented = false;

    START_TEST("Keypair tests");

    for (pos = 0; pos < cases_amount; ++pos) {
        _test_case_t *test_case = &test_cases[pos];

        test_case->initialized = false;

        TEST_KEYPAIR_NOT_IMPLEMENTED(test_case->slot, test_case->keypair_type);

        if (not_implemented) {
            VS_LOG_WARNING("Keypair type %s is not implemented",
                           vs_secmodule_keypair_type_descr(test_case->keypair_type));
            continue;
        }

        VS_IOT_STRCPY(buf, "Keypair type ");
        VS_IOT_STRCPY(buf + VS_IOT_STRLEN(buf), vs_secmodule_keypair_type_descr(test_case->keypair_type));
        VS_IOT_STRCPY(buf + VS_IOT_STRLEN(buf), ", slot ");
        VS_IOT_STRCPY(buf + VS_IOT_STRLEN(buf), vs_test_secmodule_slot_descr(test_case->slot));

        TEST_CASE_OK(buf, _test_keypair_generate(secmodule_impl, test_case));
    }

    TEST_CASE_OK("Compare buffer outputs", _compare_outputs(test_cases, cases_amount));

terminate:
    return failed_test_result;
}
