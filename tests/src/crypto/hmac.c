
#include <helpers.h>

#include <virgil/crypto/foundation/vscf_iotelic_hmac.h>
#include <virgil/crypto/foundation/vscf_iotelic_sha256.h>
#include <virgil/crypto/foundation/vscf_iotelic_sha384.h>
#include <virgil/crypto/foundation/vscf_iotelic_sha512.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

static vsc_data_t key;
static vsc_data_t input;
static vsc_data_t another_input;

/******************************************************************************/
static bool
test_hmac_step(vscf_impl_t *sha_impl, vsc_data_t correct_result) {
    vsc_buffer_t result;
    vsc_buffer_t another_result;
    vscf_iotelic_hmac_t *hmac_ctx = vscf_iotelic_hmac_new();
    bool correct;
    bool incorrect;
    static uint8_t result_buf[RESULT_BUF_SIZE];
    static uint8_t another_result_buf[RESULT_BUF_SIZE];

    vsc_buffer_init(&result);
    vsc_buffer_init(&another_result);

    vsc_buffer_use(&result, result_buf, sizeof(result_buf));
    vsc_buffer_use(&another_result, another_result_buf, sizeof(another_result));

    vscf_iotelic_hmac_take_hash(hmac_ctx, sha_impl);
    vscf_iotelic_hmac_mac(hmac_ctx, key, input, &result);
    correct = vsc_data_equal(correct_result, vsc_buffer_data(&result));

    vscf_iotelic_hmac_mac(hmac_ctx, key, another_input, &another_result);
    incorrect = !vsc_data_equal(correct_result, vsc_buffer_data(&another_result));

    vsc_buffer_cleanup(&result);
    vsc_buffer_cleanup(&another_result);
    vscf_iotelic_hmac_delete(hmac_ctx);

    return correct && incorrect;
}

/******************************************************************************/
void
test_hmac(void) {
    static const uint8_t another_raw[] = {};

    uint8_t key_raw[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    uint8_t input_raw[] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                           0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                           0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                           0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                           0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};

    uint8_t sha256_result_raw[] = {0x70, 0xa8, 0xe8, 0xa8, 0xb5, 0x24, 0x1b, 0x7e, 0x75, 0x84, 0x93,
                                   0x55, 0x3f, 0x29, 0x21, 0x80, 0x1b, 0x11, 0xd3, 0x6f, 0x47, 0x35,
                                   0xd8, 0xb5, 0xf2, 0x72, 0xa3, 0x46, 0x4b, 0x25, 0x0d, 0x9c};

    uint8_t sha384_result_raw[] = {0x7b, 0x4a, 0xf4, 0x20, 0x98, 0x0c, 0xeb, 0xfa, 0xc1, 0x42, 0xf1, 0x33,
                                   0x66, 0x9d, 0x05, 0xe5, 0x8d, 0x6d, 0x47, 0x49, 0x88, 0xd9, 0x48, 0x22,
                                   0x04, 0xa2, 0xd1, 0x70, 0xf4, 0x59, 0x2c, 0x73, 0xea, 0xd5, 0xc3, 0xf0,
                                   0x8a, 0x8e, 0xe4, 0xf1, 0x9d, 0xfa, 0x13, 0x81, 0x8a, 0xbf, 0xb7, 0xb4};

    uint8_t sha512_result_raw[] = {0x23, 0x14, 0x5c, 0xab, 0x10, 0x24, 0x1b, 0x87, 0xcc, 0x3c, 0x18, 0xb6, 0xfa,
                                   0xe4, 0x61, 0x31, 0xc0, 0x1e, 0x16, 0xef, 0x73, 0xf0, 0x38, 0x5f, 0xc6, 0x0e,
                                   0xa7, 0xc6, 0x14, 0x6d, 0x02, 0x37, 0x9e, 0xb2, 0x29, 0xa0, 0x27, 0xde, 0x37,
                                   0x21, 0xd2, 0x88, 0xac, 0x81, 0x63, 0x17, 0xe9, 0x13, 0x37, 0xb7, 0x4e, 0xde,
                                   0xf1, 0x7a, 0xb5, 0x97, 0xbc, 0x27, 0x0d, 0x23, 0x9a, 0xb8, 0xc8, 0x36};

    key = vsc_data(key_raw, sizeof(key_raw));
    input = vsc_data(input_raw, sizeof(input_raw));
    another_input = vsc_data(another_raw, sizeof(another_raw));

    START_TEST("HMAC test");

    TEST_CASE_OK("SHA-256 usage",
                 test_hmac_step(vscf_iotelic_sha256_impl(vscf_iotelic_sha256_new()),
                                vsc_data(sha256_result_raw, sizeof(sha256_result_raw))));
    TEST_CASE_OK("SHA-384 usage",
                 test_hmac_step(vscf_iotelic_sha384_impl(vscf_iotelic_sha384_new()),
                                vsc_data(sha384_result_raw, sizeof(sha384_result_raw))));
    TEST_CASE_OK("SHA-512 usage",
                 test_hmac_step(vscf_iotelic_sha512_impl(vscf_iotelic_sha512_new()),
                                vsc_data(sha512_result_raw, sizeof(sha512_result_raw))));

terminate:;
}