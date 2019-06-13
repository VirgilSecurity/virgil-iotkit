#include <helpers.h>
/*
#include <virgil/crypto/foundation/vscf_iotelic_sha256.h>
#include <virgil/crypto/foundation/vscf_iotelic_sha384.h>
#include <virgil/crypto/foundation/vscf_iotelic_sha512.h>
#include <virgil/crypto/foundation/vscf_iotelic_private_key.h>
#include <virgil/crypto/foundation/vscf_iotelic_public_key.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <iotelic_slots.h>

******************************************************************************
static bool
_test_sign_verify_pass(vs_iot_hsm_slot_e slot, vscf_alg_id_t hash_alg, vscf_alg_id_t keygen_alg) {
    static const char *input_data_raw = "Test data";
    vsc_data_t input_data;
    uint8_t hash_buf[/ * RESULT_BUF_SIZE * / 100];
    vsc_buffer_t hash;
    vscf_iotelic_private_key_t *ctx_prvkey = NULL;
    vscf_iotelic_public_key_t *ctx_pubkey = NULL;
    uint8_t sign_buf[RESULT_BUF_SIZE];
    vsc_buffer_t sign;
    bool success = false;

    vsc_buffer_init(&hash);
    vsc_buffer_init(&sign);

    input_data = vsc_data((const byte *)input_data_raw, strlen(input_data_raw));
    vsc_buffer_use(&hash, hash_buf, sizeof(hash_buf));
    vsc_buffer_use(&sign, sign_buf, sizeof(sign_buf));

    ctx_prvkey = vscf_iotelic_private_key_new();

    VSCF_CHECK_GOTO(vscf_iotelic_private_key_generate_key(ctx_prvkey, slot, keygen_alg),
                    "ERROR while generating keypair");

    switch (hash_alg) {
    case vscf_alg_id_SHA256:
        vscf_iotelic_sha256_hash(input_data, &hash);
        break;
    case vscf_alg_id_SHA384:
        vscf_iotelic_sha384_hash(input_data, &hash);
        break;
    case vscf_alg_id_SHA512:
        vscf_iotelic_sha512_hash(input_data, &hash);
        break;

    default:
        VS_LOG_ERROR("Unsupported hash mode");
        goto terminate;
    }

    VSCF_CHECK_GOTO(vscf_iotelic_private_key_sign_hash(ctx_prvkey, vsc_buffer_data(&hash), hash_alg, &sign),
                    "ERROR while signing hash");

    ctx_pubkey = vscf_iotelic_public_key_new();

    VSCF_CHECK_GOTO(vscf_iotelic_public_key_import_from_slot_id(ctx_pubkey, slot),
                    "ERROR while importing public key from slot");

    BOOL_CHECK_GOTO(
            vscf_iotelic_public_key_verify_hash(ctx_pubkey, vsc_buffer_data(&hash), hash_alg, vsc_buffer_data(&sign)),
            "ERROR while verifying hash");

    success = true;

terminate:

    vscf_iotelic_private_key_delete(ctx_prvkey);
    vscf_iotelic_public_key_delete(ctx_pubkey);
    vsc_buffer_cleanup(&hash);
    vsc_buffer_cleanup(&sign);

    return success;
}
*/

/******************************************************************************/
void
test_ecdsa(void) {
#if 0
#define TEST_SIGN_VERIFY_PASS(SLOT, HASH, KEY)                                                                         \
    TEST_CASE_OK("slot " #SLOT ", hash " #HASH ", key " #KEY, _test_sign_verify_pass(SLOT, HASH, KEY));
    START_TEST("ECDSA Sign/Verify tests");

    TEST_SIGN_VERIFY_PASS(KEY_SLOT_STD_MTP_1, vscf_alg_id_SHA256, vscf_alg_id_SECP256R1);

    TEST_SIGN_VERIFY_PASS(KEY_SLOT_STD_MTP_2, vscf_alg_id_SHA384, vscf_alg_id_SECP256R1);

    TEST_SIGN_VERIFY_PASS(KEY_SLOT_STD_MTP_6, vscf_alg_id_SHA512, vscf_alg_id_SECP256R1);

    TEST_SIGN_VERIFY_PASS(KEY_SLOT_STD_MTP_4, vscf_alg_id_SHA256, vscf_alg_id_ED25519);

    TEST_SIGN_VERIFY_PASS(KEY_SLOT_STD_MTP_5, vscf_alg_id_SHA384, vscf_alg_id_ED25519);

    TEST_SIGN_VERIFY_PASS(KEY_SLOT_STD_MTP_6, vscf_alg_id_SHA512, vscf_alg_id_ED25519);

#if 0
    TEST_SIGN_VERIFY_PASS(
            KEY_SLOT_STD_OTP_2, vscf_alg_id_SHA384, vscf_alg_id_CURVE25519 /*KEYPAIR_RSA_2048 */ /*, SIGN_PSS */);

    TEST_SIGN_VERIFY_PASS(
            KEY_SLOT_STD_OTP_3, vscf_alg_id_SHA512, vscf_alg_id_CURVE25519 /*KEYPAIR_RSA_3072 */ /*, SIGN_COMMON */);

    TEST_SIGN_VERIFY_PASS(
            KEY_SLOT_STD_OTP_0, vscf_alg_id_SHA256, vscf_alg_id_CURVE25519 /*KEYPAIR_RSA_4096 */ /*, SIGN_COMMON */);
#endif
terminate:;

#undef TEST_SIGN_VERIFY_PASS
#endif
}
