#include <helpers.h>
#include <private_helpers.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <stdlib-config.h>

typedef struct {
    vs_iot_hsm_slot_e slot;
    vs_hsm_keypair_type_e keypair_type;
    uint8_t buf[PUBKEY_MAX_BUF_SIZE];
    uint16_t key_sz;
    uint16_t expected_size;
    bool initialized;
} _test_case_t;

/******************************************************************************/
static bool
_is_keypair_type_implemented(_test_case_t *test_case) {

    return VS_HSM_ERR_NOT_IMPLEMENTED != vs_hsm_keypair_create(test_case->slot, test_case->keypair_type);
}

/******************************************************************************/
static bool
_test_keypair_generate(_test_case_t *test_case) {
    vs_hsm_keypair_type_e keypair;

    test_case->initialized = true;

    VS_HSM_CHECK_RET(vs_hsm_keypair_create(test_case->slot, test_case->keypair_type),
                     "vs_hsm_keypair_create call error");
    VS_HSM_CHECK_RET(vs_hsm_keypair_get_pubkey(
                             test_case->slot, test_case->buf, sizeof(test_case->buf), &test_case->key_sz, &keypair),
                     "vs_hsm_keypair_get_pubkey call error");
    BOOL_CHECK_RET(keypair == test_case->keypair_type, "Received key pair type error");
    BOOL_CHECK_RET(test_case->key_sz == test_case->expected_size, "Received buffer error");

    // TODO : check sign/verify for keypair

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
                        vs_hsm_keypair_type_descr(test_cases[pos].keypair_type),
                        test_cases[pos2].slot,
                        vs_hsm_keypair_type_descr(test_cases[pos2].keypair_type));

                return false;
            }
        }
    }

    return true;
}

/******************************************************************************/
void
test_keypair(void) {

    _test_case_t test_cases[] = {
#if USE_RSA
        {.slot = VS_KEY_SLOT_EXT_MTP_0, .keypair_type = VS_KEYPAIR_RSA_2048, .expected_size = 256},
#endif // USE_RSA
        {.slot = VS_KEY_SLOT_STD_MTP_0, .keypair_type = VS_KEYPAIR_EC_SECP192R1, .expected_size = 49},
        {.slot = VS_KEY_SLOT_STD_MTP_1, .keypair_type = VS_KEYPAIR_EC_SECP224R1, .expected_size = 57},
        {.slot = VS_KEY_SLOT_STD_MTP_2, .keypair_type = VS_KEYPAIR_EC_SECP256R1, .expected_size = 65},
        {.slot = VS_KEY_SLOT_STD_MTP_3, .keypair_type = VS_KEYPAIR_EC_SECP384R1, .expected_size = 97},
        {.slot = VS_KEY_SLOT_EXT_TMP_0, .keypair_type = VS_KEYPAIR_EC_SECP521R1, .expected_size = 133},
        {.slot = VS_KEY_SLOT_STD_MTP_4, .keypair_type = VS_KEYPAIR_EC_SECP192K1, .expected_size = 49},
        {.slot = VS_KEY_SLOT_STD_MTP_5, .keypair_type = VS_KEYPAIR_EC_SECP224K1, .expected_size = 57},
        {.slot = VS_KEY_SLOT_STD_MTP_6, .keypair_type = VS_KEYPAIR_EC_SECP256K1, .expected_size = 65},
        {.slot = VS_KEY_SLOT_STD_MTP_7, .keypair_type = VS_KEYPAIR_EC_CURVE25519, .expected_size = 32},
        {.slot = VS_KEY_SLOT_STD_MTP_8, .keypair_type = VS_KEYPAIR_EC_ED25519, .expected_size = 32}
    };

    static const size_t cases_amount = sizeof(test_cases) / sizeof(test_cases[0]);
    size_t pos;
    char buf[256];
    vs_log_level_t default_loglev;

    START_TEST("Keypair tests");

    default_loglev = vs_logger_get_loglev();

    for (pos = 0; pos < cases_amount; ++pos) {
        _test_case_t *test_case = &test_cases[pos];

        test_case->initialized = false;

        vs_logger_set_loglev(VS_LOGLEV_CRITICAL);
        if (!_is_keypair_type_implemented(test_case)) {
            vs_logger_set_loglev(VS_LOGLEV_WARNING);
            VS_LOG_WARNING("Keypair type %s is not implemented", vs_hsm_keypair_type_descr(test_case->keypair_type));
            continue;
        }
        vs_logger_set_loglev(default_loglev);

        VS_IOT_STRCPY(buf, "Keypair type ");
        VS_IOT_STRCPY(buf + VS_IOT_STRLEN(buf), vs_hsm_keypair_type_descr(test_case->keypair_type));
        VS_IOT_STRCPY(buf + VS_IOT_STRLEN(buf), ", slot ");
        VS_IOT_STRCPY(buf + VS_IOT_STRLEN(buf), vs_iot_hsm_slot_descr(test_case->slot));

        TEST_CASE_OK(buf, _test_keypair_generate(test_case));
    }

    vs_logger_set_loglev(default_loglev);

    TEST_CASE_OK("Compare buffer outputs", _compare_outputs(test_cases, cases_amount));

terminate:;
}
