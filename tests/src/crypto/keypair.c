#include <helpers.h>
#include <virgil/iot/hsm/hsm_structs.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <stdlib-config.h>

typedef struct {
    vs_iot_hsm_slot_e slot;
    vs_hsm_keypair_type_e keypair_type;
    const char *descr;
    uint8_t *buf;
    uint16_t key_sz;
    uint16_t waited_size;
} _test_case_t;

/******************************************************************************/
static bool
_test_keypair_generate(_test_case_t *test_case){
    vs_hsm_keypair_type_e keypair;

    test_case->buf = NULL;
    keypair = test_case->keypair_type;

    VS_HSM_CHECK_RET(vs_hsm_keypair_create(test_case->slot, test_case->keypair_type), "vs_hsm_keypair_create call error");
    VS_HSM_CHECK_RET(vs_hsm_keypair_get_pubkey(test_case->slot, &test_case->buf, sizeof(test_case->buf), &test_case->key_sz, &keypair), "vs_hsm_keypair_get_pubkey call error");
    BOOL_CHECK_RET(keypair == test_case->keypair_type && test_case->buf != NULL && test_case->key_sz == test_case->waited_size, "Received buffers error");

    // TODO : check sign/verify for keypair

    return true;
}

/******************************************************************************/
static bool
_compare_outputs(_test_case_t *test_cases, size_t cases_amount) {

    size_t pos;
    size_t pos2;

    for(pos = 0; pos < cases_amount; ++pos){
        for(pos2 = pos + 1; pos2 < cases_amount; ++pos2){
            if(test_cases[pos].key_sz != test_cases[pos2].key_sz){
                continue;
            }

            if(VS_IOT_MEMCMP(test_cases[pos].buf, test_cases[pos2].buf, test_cases[pos].key_sz) == 0) {
                VS_LOG_ERROR(
                        "The same keys are generated for (slot = %d, key type = %d) and (slot = %d, key type = %d)",
                        test_cases[pos].slot,
                        test_cases[pos].keypair_type,
                        test_cases[pos2].slot,
                        test_cases[pos2].keypair_type);

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
            { .buf = NULL, .slot = VS_KEY_SLOT_EXT_MTP_0, .keypair_type = VS_KEYPAIR_RSA_2048,       .waited_size = 256, .descr = "RSA 2048 bit (VS_KEYPAIR_RSA_2048)" },
#endif // USE_RSA
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_0, .keypair_type = VS_KEYPAIR_EC_SECP192R1  , .waited_size = 49, .descr = "192-bits NIST curve (VS_KEYPAIR_EC_SECP192R1)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_1, .keypair_type = VS_KEYPAIR_EC_SECP224R1  , .waited_size = 57, .descr = "224-bits NIST curve (VS_KEYPAIR_EC_SECP224R1)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_2, .keypair_type = VS_KEYPAIR_EC_SECP256R1  , .waited_size = 65, .descr = "256-bits NIST curve (VS_KEYPAIR_EC_SECP256R1)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_3, .keypair_type = VS_KEYPAIR_EC_SECP384R1  , .waited_size = 97, .descr = "384-bits NIST curve (VS_KEYPAIR_EC_SECP384R1)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_EXT_TMP_0, .keypair_type = VS_KEYPAIR_EC_SECP521R1  , .waited_size = 133, .descr = "521-bits NIST curve (VS_KEYPAIR_EC_SECP521R1)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_4, .keypair_type = VS_KEYPAIR_EC_SECP192K1  , .waited_size = 49, .descr = "192-bits \"Koblitz\" curve (VS_KEYPAIR_EC_SECP192K1)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_5, .keypair_type = VS_KEYPAIR_EC_SECP224K1  , .waited_size = 57, .descr = "224-bits \"Koblitz\" curve (VS_KEYPAIR_EC_SECP224K1)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_6, .keypair_type = VS_KEYPAIR_EC_SECP256K1  , .waited_size = 65, .descr = "256-bits \"Koblitz\" curve (VS_KEYPAIR_EC_SECP256K1)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_7, .keypair_type = VS_KEYPAIR_EC_CURVE25519 , .waited_size = 32, .descr = "Curve25519 (VS_KEYPAIR_EC_CURVE25519)" },
            { .buf = NULL, .slot = VS_KEY_SLOT_STD_MTP_8, .keypair_type = VS_KEYPAIR_EC_ED25519    , .waited_size = 32, .descr = "Ed25519 (VS_KEYPAIR_EC_ED25519)" }
    };

    static const size_t cases_amount = sizeof(test_cases) / sizeof(test_cases[0]);
    size_t pos;

    START_TEST("Keypair tests");

    for(pos = 0; pos < cases_amount; ++pos){
        _test_case_t *test_case = &test_cases[pos];

        TEST_CASE_OK(test_case->descr, _test_keypair_generate(test_case));
    }

    TEST_CASE_OK("Compare buffer outputs", _compare_outputs(test_cases, cases_amount));

    terminate: ;

    for(pos = 0; pos < cases_amount; ++pos){
        VS_IOT_FREE(test_cases[pos].buf);
    }

}
