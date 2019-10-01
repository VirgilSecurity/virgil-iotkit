#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/tests/private/private_helpers.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>

/*******************************************************************************/
static bool
_create_keypairs_() {
#define TEST_AND_CREATE(SLOT, KEYPAIR)                                                                                 \
    do {                                                                                                               \
        TEST_KEYPAIR_NOT_IMPLEMENTED((SLOT), (KEYPAIR));                                                               \
        if (not_implemented) {                                                                                         \
            VS_LOG_WARNING("Keypair type %s is not implemented", vs_hsm_keypair_type_descr(KEYPAIR));                  \
        } else {                                                                                                       \
            VS_HSM_CHECK_RET(vs_hsm_keypair_create((SLOT), (KEYPAIR)),                                                 \
                             "Unable to create keypair %s for slot %d (%s) while preparing test",                      \
                             vs_hsm_keypair_type_descr(KEYPAIR),                                                       \
                             (SLOT),                                                                                   \
                             vs_iot_hsm_slot_descr(SLOT));                                                             \
        }                                                                                                              \
    } while (0)

    bool not_implemented = false;

    TEST_AND_CREATE(VS_KEY_SLOT_STD_MTP_8, VS_KEYPAIR_EC_SECP192R1);
    TEST_AND_CREATE(VS_KEY_SLOT_STD_MTP_9, VS_KEYPAIR_EC_SECP192K1);
    TEST_AND_CREATE(VS_KEY_SLOT_STD_MTP_10, VS_KEYPAIR_EC_SECP224R1);
    TEST_AND_CREATE(VS_KEY_SLOT_STD_MTP_11, VS_KEYPAIR_EC_SECP224K1);
    TEST_AND_CREATE(VS_KEY_SLOT_STD_MTP_12, VS_KEYPAIR_EC_SECP256R1);
    TEST_AND_CREATE(VS_KEY_SLOT_STD_MTP_13, VS_KEYPAIR_EC_SECP256K1);
    TEST_AND_CREATE(VS_KEY_SLOT_STD_MTP_14, VS_KEYPAIR_EC_SECP384R1);
    TEST_AND_CREATE(VS_KEY_SLOT_EXT_MTP_0, VS_KEYPAIR_EC_SECP521R1);
    TEST_AND_CREATE(VS_KEY_SLOT_STD_MTP_0, VS_KEYPAIR_EC_ED25519);

    return true;

#undef TEST_AND_CREATE
}

/*******************************************************************************/
static bool
_test_sign_verify_pass(vs_iot_hsm_slot_e slot, vs_hsm_hash_type_e hash_alg, vs_hsm_keypair_type_e keypair_type) {
    static const char *input_data_raw = "Test data";
    uint16_t result_sz;
    uint8_t hash_buf[HASH_MAX_BUF_SIZE];
    uint8_t pubkey[PUBKEY_MAX_BUF_SIZE];
    uint16_t pubkey_sz;
    vs_hsm_keypair_type_e pubkey_type;
    uint8_t sign_buf[RESULT_BUF_SIZE];
    uint16_t signature_sz;

    VS_HSM_CHECK_RET(vs_hsm_hash_create(hash_alg,
                                        (uint8_t *)input_data_raw,
                                        strlen(input_data_raw),
                                        hash_buf,
                                        sizeof(hash_buf),
                                        &result_sz),
                     "ERROR while creating hash");

    signature_sz = sizeof(sign_buf);

    VS_HSM_CHECK_RET(vs_hsm_ecdsa_sign(slot, hash_alg, hash_buf, sign_buf, signature_sz, &signature_sz),
                     "ERROR while signing hash");

    BOOL_CHECK_RET(signature_sz == vs_hsm_get_signature_len(keypair_type), "ERROR Invalid signature size");

    VS_HSM_CHECK_RET(vs_hsm_keypair_get_pubkey(slot, pubkey, sizeof(pubkey), &pubkey_sz, &pubkey_type),
                     "ERROR while importing public key from slot");

    VS_HSM_CHECK_RET(vs_hsm_ecdsa_verify(keypair_type, pubkey, pubkey_sz, hash_alg, hash_buf, sign_buf, signature_sz),
                     "ERROR while verifying hash");

    return true;
}

/******************************************************************************/
static bool
_prepare_and_test(char *descr, vs_iot_hsm_slot_e slot, vs_hsm_hash_type_e hash, vs_hsm_keypair_type_e keypair_type) {
    bool not_implemented = false;

    VS_IOT_STRCPY(descr, "slot ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_iot_hsm_slot_descr(slot));
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", hash ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_hsm_hash_type_descr(hash));
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", keypair type ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_hsm_keypair_type_descr(keypair_type));

    TEST_KEYPAIR_NOT_IMPLEMENTED(slot, keypair_type);
    if (not_implemented) {
        VS_LOG_WARNING("Keypair type %s is not implemented", vs_hsm_keypair_type_descr(keypair_type));
        return false;
    }

    TEST_HASH_NOT_IMPLEMENTED(hash);
    if (not_implemented) {
        VS_LOG_WARNING("Hash %s is not implemented", vs_hsm_hash_type_descr(hash));
        return false;
    }

    return true;
}

/******************************************************************************/
uint16_t
test_ecdsa(void) {
    uint16_t failed_test_result = 0;

#define TEST_SIGN_VERIFY_PASS(SLOT, HASH, KEY)                                                                         \
    VS_IOT_STRCPY(descr, "slot ");                                                                                     \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_iot_hsm_slot_descr(SLOT));                                          \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", hash ");                                                            \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_hsm_hash_type_descr(HASH));                                         \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", keypair type ");                                                    \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_hsm_keypair_type_descr(KEY));                                       \
                                                                                                                       \
    if (_prepare_and_test(descr, (SLOT), (HASH), (KEY))) {                                                             \
        TEST_CASE_OK(descr, _test_sign_verify_pass(SLOT, HASH, KEY));                                                  \
    }

    char descr[256];

    START_TEST("ECDSA Sign/Verify tests");

    if (!_create_keypairs_()) {
        return failed_test_result;
    }

    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_8, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP192R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_9, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP192K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_10, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP224R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_11, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP224K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_12, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP256R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_13, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP256K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_14, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP384R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP521R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_0, VS_HASH_SHA_256, VS_KEYPAIR_EC_ED25519)

    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_8, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP192R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_9, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP192K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_10, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP224R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_11, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP224K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_12, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP256R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_13, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP256K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_14, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP384R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP521R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_0, VS_HASH_SHA_384, VS_KEYPAIR_EC_ED25519)

    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_8, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP192R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_9, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP192K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_10, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP224R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_11, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP224K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_12, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP256R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_13, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP256K1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_14, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP384R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP521R1)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_0, VS_HASH_SHA_512, VS_KEYPAIR_EC_ED25519)

#if USE_RSA
    if (VS_HSM_ERR_OK != vs_hsm_keypair_create(VS_KEY_SLOT_EXT_MTP_0, VS_KEYPAIR_RSA_2048)) {
        return failed_test_result + 1;
    }

    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_256, VS_KEYPAIR_RSA_2048)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_384, VS_KEYPAIR_RSA_2048)
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_512, VS_KEYPAIR_RSA_2048)
#endif
terminate:
    return failed_test_result;

#undef TEST_SIGN_VERIFY_PASS
}
