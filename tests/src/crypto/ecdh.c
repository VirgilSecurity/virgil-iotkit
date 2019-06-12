#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <crypto/iot_crypto.h>
#include <crypto/iot_data.h>

#include "iot_crypto.h"

/******************************************************************************/
static bool
_test_ecdh_pass(iot_crypto_keypair_type_t keypair_type, bool corrupt_key) {
    const iot_crypto_slot_t alise_slot = KEY_SLOT_MTP_1;
    const iot_crypto_slot_t bob_slot = KEY_SLOT_MTP_2;

    IOT_CRYPTO_PUBLIC_KEY(alise_public_key);
    IOT_CRYPTO_PUBLIC_KEY(bob_public_key);
    IOT_DATA(shared_secret_1, 128);
    IOT_DATA(shared_secret_2, 128);

    // Create key pair for Alise
    BOOL_CHECK_RET(IOT_CRYPTO_OK == iot_crypto_keypair_create(alise_slot, keypair_type),
                   "Can't create keypair for Alise (%s)",
                   iot_crypto_keypair_name(keypair_type));

    BOOL_CHECK_RET(IOT_CRYPTO_OK == iot_crypto_keypair_get_pubkey(alise_slot, &alise_public_key),
                   "Can't load public key from slot for Alise (%s)",
                   iot_crypto_keypair_name(keypair_type));

    if (corrupt_key) {
        ++alise_public_key.key_data.data[1];
    }

    // Create key pair for Bob
    BOOL_CHECK_RET(IOT_CRYPTO_OK == iot_crypto_keypair_create(bob_slot, keypair_type),
                   "Can't create keypair for Bob (%s)",
                   iot_crypto_keypair_name(keypair_type));

    BOOL_CHECK_RET(IOT_CRYPTO_OK == iot_crypto_keypair_get_pubkey(bob_slot, &bob_public_key),
                   "Can't load public key from slot for Bob (%s)",
                   iot_crypto_keypair_name(keypair_type));

    // ECDH for Alise - Bob
    BOOL_CHECK_RET(IOT_CRYPTO_OK == iot_crypto_ecdh(alise_slot, &bob_public_key, &shared_secret_1),
                   "Can't process ECDH for Alise (%s)",
                   iot_crypto_keypair_name(keypair_type));

    // ECDH for Bob - Alise
    if (IOT_CRYPTO_OK != iot_crypto_ecdh(bob_slot, &alise_public_key, &shared_secret_2)) {
        if (!corrupt_key) {
            CRYPTO_LOG("Can't process ECDH for Bob (%s)", iot_crypto_keypair_name(keypair_type));
        }
        return false;
    }

    // Compare shared secrets
    MEMCMP_BOOL_CHECK_RET(shared_secret_1.data, shared_secret_2.data, shared_secret_1.data_sz);

    return false;
}

/******************************************************************************/
bool
test_ecdh(void) {
    // Pass
    if (!_test_ecdh_pass(KEYPAIR_EC_SECP256R1, false))
        return false;
    if (!_test_ecdh_pass(KEYPAIR_EC_SECP384R1, false))
        return false;
    if (!_test_ecdh_pass(KEYPAIR_EC_SECP521R1, false))
        return false;
    if (!_test_ecdh_pass(KEYPAIR_EC_ED25519, false))
        return false;
    if (!_test_ecdh_pass(KEYPAIR_EC_CURVE25519, false))
        return false;

    // Fail
    if (_test_ecdh_pass(KEYPAIR_EC_SECP256R1, true))
        return false;
    if (_test_ecdh_pass(KEYPAIR_EC_CURVE25519, true))
        return false;

    return true;
}
