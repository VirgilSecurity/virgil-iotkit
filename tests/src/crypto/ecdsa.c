#include <virgil/iot/tests/helpers.h>
#include <private/private_helpers.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

/*******************************************************************************/
static bool
_test_sign_verify_pass(vs_secmodule_impl_t *secmodule_impl,
                       vs_iot_secmodule_slot_e slot,
                       vs_secmodule_hash_type_e hash_alg,
                       vs_secmodule_keypair_type_e keypair_type) {
    static const char *input_data_raw = "Test data";
    uint16_t result_sz;
    uint8_t hash_buf[HASH_MAX_BUF_SIZE];
    uint8_t pubkey[PUBKEY_MAX_BUF_SIZE];
    uint16_t pubkey_sz;
    vs_secmodule_keypair_type_e pubkey_type;
    uint8_t sign_buf[RESULT_BUF_SIZE];
    uint16_t signature_sz;

    STATUS_CHECK_RET_BOOL(secmodule_impl->hash(hash_alg,
                                               (uint8_t *)input_data_raw,
                                               VS_IOT_STRLEN(input_data_raw),
                                               hash_buf,
                                               sizeof(hash_buf),
                                               &result_sz),
                          "ERROR while creating hash");

    signature_sz = sizeof(sign_buf);

    STATUS_CHECK_RET_BOOL(secmodule_impl->ecdsa_sign(slot, hash_alg, hash_buf, sign_buf, signature_sz, &signature_sz),
                          "ERROR while signing hash");

    BOOL_CHECK_RET(signature_sz == vs_secmodule_get_signature_len(keypair_type), "ERROR Invalid signature size");

    STATUS_CHECK_RET_BOOL(secmodule_impl->get_pubkey(slot, pubkey, sizeof(pubkey), &pubkey_sz, &pubkey_type),
                          "ERROR while importing public key from slot");

    STATUS_CHECK_RET_BOOL(
            secmodule_impl->ecdsa_verify(keypair_type, pubkey, pubkey_sz, hash_alg, hash_buf, sign_buf, signature_sz),
            "ERROR while verifying hash");

    return true;
}

/******************************************************************************/
static bool
_prepare_and_test(vs_secmodule_impl_t *secmodule_impl,
                  char *descr,
                  vs_iot_secmodule_slot_e slot,
                  vs_secmodule_hash_type_e hash,
                  vs_secmodule_keypair_type_e keypair_type) {
    bool not_implemented = false;

    VS_IOT_STRCPY(descr, "slot ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_test_secmodule_slot_descr(slot));
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", hash ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_secmodule_hash_type_descr(hash));
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", keypair type ");
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_secmodule_keypair_type_descr(keypair_type));

    TEST_KEYPAIR_NOT_IMPLEMENTED(slot, keypair_type);
    if (not_implemented) {
        VS_LOG_WARNING("Keypair type %s is not implemented", vs_secmodule_keypair_type_descr(keypair_type));
        return false;
    }

    TEST_HASH_NOT_IMPLEMENTED(hash);
    if (not_implemented) {
        VS_LOG_WARNING("Hash %s is not implemented", vs_secmodule_hash_type_descr(hash));
        return false;
    }

    return true;
}

/******************************************************************************/
uint16_t
test_ecdsa(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;

#define TEST_SIGN_VERIFY_PASS(SLOT, HASH, KEY)                                                                         \
    VS_IOT_STRCPY(descr, "slot ");                                                                                     \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_test_secmodule_slot_descr(SLOT));                                   \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", hash ");                                                            \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_secmodule_hash_type_descr(HASH));                                   \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), ", keypair type ");                                                    \
    VS_IOT_STRCPY(descr + VS_IOT_STRLEN(descr), vs_secmodule_keypair_type_descr(KEY));                                 \
                                                                                                                       \
    if (_prepare_and_test(secmodule_impl, descr, (SLOT), (HASH), (KEY))) {                                             \
        TEST_CASE_OK(descr, _test_sign_verify_pass(secmodule_impl, SLOT, HASH, KEY));                                  \
    }

    char descr[256];

    START_TEST("ECDSA Sign/Verify tests");

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

terminate:
    return failed_test_result;

#undef TEST_SIGN_VERIFY_PASS
}
