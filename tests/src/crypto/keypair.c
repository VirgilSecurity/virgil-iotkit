#include <helpers.h>

#if 0
#include <virgil/crypto/foundation/vscf_iotelic_private_key.h>
#include <virgil/crypto/foundation/vscf_iotelic_public_key.h>
#include <iotelic_slots.h>

/******************************************************************************/
static bool
_test_create_fail(vs_iot_hsm_slot_e key_slot, vscf_alg_id_t keypair_type) {

    bool success = true;
    vscf_iotelic_private_key_t *ctx_prvkey = NULL;
    ctx_prvkey = vscf_iotelic_private_key_new();

    BOOL_CHECK_GOTO(vscf_status_SUCCESS != vscf_iotelic_private_key_generate_key(ctx_prvkey, key_slot, keypair_type),
                    "Success result with wrong input data. So, it's bug.");
    success = false;

terminate:
    vscf_iotelic_private_key_delete(ctx_prvkey);

    return success;
}

/******************************************************************************/
static bool
_test_create_key(vs_iot_hsm_slot_e key_slot, vscf_alg_id_t keypair_type) {

    bool success = false;
    vscf_iotelic_private_key_t *ctx_prvkey = NULL;
    ctx_prvkey = vscf_iotelic_private_key_new();

    VSCF_CHECK_GOTO(vscf_iotelic_private_key_generate_key(ctx_prvkey, key_slot, keypair_type),
                    "keypair can't be created");
    success = true;

terminate:
    vscf_iotelic_private_key_delete(ctx_prvkey);

    return success;
}

/******************************************************************************/
static bool
_test_key_get_ED25519_pass() {
    int res = 0;
    if (!_test_create_key(KEY_SLOT_STD_MTP_1, vscf_alg_id_ED25519)) {
        return false;
    }

    vscf_iotelic_public_key_t *pubkey = NULL;

    pubkey = vscf_iotelic_public_key_new();

    if (vscf_status_SUCCESS != vscf_iotelic_public_key_import_from_slot_id(pubkey, KEY_SLOT_STD_MTP_1)) {
        res = -1;
    }

    vscf_iotelic_public_key_delete(pubkey);

    return (res == 0);
}
#endif
/******************************************************************************/
void
test_keypair(void) {
#if 0
    START_TEST("Keypair tests");

    TEST_CASE_OK("Key slot MTP 1, secp256r1", _test_create_key(KEY_SLOT_STD_MTP_1, vscf_alg_id_SECP256R1));
    TEST_CASE_OK("Key slot MTP 2, ED25519", _test_create_key(KEY_SLOT_STD_MTP_2, vscf_alg_id_ED25519));
    TEST_CASE_OK("Key slot MTP 3, CURVE25519", _test_create_key(KEY_SLOT_STD_MTP_3, vscf_alg_id_CURVE25519));
    TEST_CASE_OK("Get ED25519 public key", _test_key_get_ED25519_pass());
    TEST_CASE_NOT_OK("Create keypair fail", _test_create_fail(KEY_SLOT_STD_MTP_0, vscf_alg_id_NONE))

#if defined(USE_RSA)
    TEST_CASE_OK("Key slot EXT MTP 0, RSA 2048", _test_create_key(KEY_SLOT_EXT_MTP_0, vscf_alg_id_RSA));
    TEST_CASE_NOT_OK("Create RSA keypair fail", _test_create_fail(KEY_SLOT_STD_MTP_0, vscf_alg_id_RSA))
#endif
terminate:;
#endif
}
