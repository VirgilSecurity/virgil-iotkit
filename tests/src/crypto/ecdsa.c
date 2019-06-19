#include <helpers.h>
#include <virgil/iot/hsm/hsm_interface.h>

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

    VS_HSM_CHECK_RET(vs_hsm_keypair_create(slot, keypair_type), "ERROR while generating keypair");
    VS_HSM_CHECK_RET(vs_hsm_hash_create(hash_alg,
                                        (uint8_t *)input_data_raw,
                                        strlen(input_data_raw),
                                        hash_buf,
                                        sizeof(hash_buf),
                                        &result_sz),
                     "ERROR while creating hash");

    VS_HSM_CHECK_RET(vs_hsm_ecdsa_sign(slot, hash_alg, hash_buf, sign_buf, sizeof(sign_buf), &signature_sz),
                     "ERROR while signing hash");
    BOOL_CHECK_RET(signature_sz == vs_hsm_get_signature_len(keypair_type), "ERROR Invalid signature size");

    VS_HSM_CHECK_RET(vs_hsm_keypair_get_pubkey(slot, pubkey, sizeof(pubkey), &pubkey_sz, &pubkey_type),
                     "ERROR while importing public key from slot");

    VS_HSM_CHECK_RET(vs_hsm_ecdsa_verify(keypair_type, pubkey, pubkey_sz, hash_alg, hash_buf, sign_buf, signature_sz),
                     "ERROR while verifying hash");

    return true;
}


/******************************************************************************/
void
test_ecdsa(void) {
#define TEST_SIGN_VERIFY_PASS(SLOT, HASH, KEY)                                                                         \
    TEST_CASE_OK("slot " #SLOT ", hash " #HASH ", key " #KEY, _test_sign_verify_pass(SLOT, HASH, KEY));
    START_TEST("ECDSA Sign/Verify tests");

    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_8, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP192R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_9, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP192K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_10, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP224R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_11, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP224K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_12, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP256R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_13, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP256K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_14, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP384R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_256, VS_KEYPAIR_EC_SECP521R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_0, VS_HASH_SHA_256, VS_KEYPAIR_EC_ED25519);

    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_8, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP192R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_9, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP192K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_10, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP224R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_11, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP224K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_12, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP256R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_13, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP256K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_14, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP384R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_384, VS_KEYPAIR_EC_SECP521R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_0, VS_HASH_SHA_384, VS_KEYPAIR_EC_ED25519);

    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_8, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP192R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_9, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP192K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_10, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP224R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_11, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP224K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_12, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP256R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_13, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP256K1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_14, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP384R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_512, VS_KEYPAIR_EC_SECP521R1);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_STD_MTP_0, VS_HASH_SHA_512, VS_KEYPAIR_EC_ED25519);

#if USE_RSA
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_256, VS_KEYPAIR_RSA_2048);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_384, VS_KEYPAIR_RSA_2048);
    TEST_SIGN_VERIFY_PASS(VS_KEY_SLOT_EXT_MTP_0, VS_HASH_SHA_512, VS_KEYPAIR_RSA_2048);
#endif
terminate:;

#undef TEST_SIGN_VERIFY_PASS
}
