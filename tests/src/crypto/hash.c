
#include <helpers.h>

#include <virgil/crypto/foundation/vscf_iotelic_sha256.h>
#include <virgil/crypto/foundation/vscf_iotelic_sha384.h>
#include <virgil/crypto/foundation/vscf_iotelic_sha512.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

static const char *test_data = "Data for hash creation ...";
static const char *another_test_data = "Another data for hash creation ...";

typedef struct {
    const uint8_t *correct_result_raw;
    size_t correct_result_size;
    void (*funct)(vsc_data_t data, vsc_buffer_t *digest);
} vs_test_data_t;

/******************************************************************************/
static bool
_test_sha_pass(const vs_test_data_t *test) {
    vsc_data_t input;
    vsc_buffer_t result;
    vsc_buffer_t another_result;
    bool correct;
    bool incorrect;
    static uint8_t result_buf[RESULT_BUF_SIZE];
    static uint8_t another_result_buf[RESULT_BUF_SIZE];

    vsc_buffer_init(&result);
    vsc_buffer_init(&another_result);

    vsc_buffer_use(&result, result_buf, sizeof(result_buf));
    vsc_buffer_use(&another_result, another_result_buf, sizeof(another_result));

    input = vsc_data((const byte *)test_data, strlen(test_data));
    test->funct(input, &result);
    correct = vsc_data_equal(vsc_data(test->correct_result_raw, test->correct_result_size), vsc_buffer_data(&result));

    input = vsc_data((const byte *)another_test_data, sizeof(another_test_data));
    test->funct(input, &another_result);
    incorrect = !vsc_data_equal(vsc_data((const byte *)another_test_data, strlen(another_test_data)),
                                vsc_buffer_data(&another_result));

    vsc_buffer_cleanup(&result);
    vsc_buffer_cleanup(&another_result);

    return correct && incorrect;
}

static const uint8_t correct_result_sha_256_raw[] = {0xef, 0x25, 0x84, 0xbc, 0x6f, 0xaf, 0x4a, 0x77, 0xff, 0x32, 0xe7,
                                                     0x45, 0x82, 0x62, 0xef, 0x89, 0x08, 0x8e, 0x93, 0x88, 0x64, 0x67,
                                                     0xa2, 0xc8, 0x19, 0xbd, 0x99, 0x60, 0xb8, 0x6e, 0xfb, 0x16};
static const vs_test_data_t sha256_test_data = {.correct_result_raw = correct_result_sha_256_raw,
                                                .correct_result_size = sizeof(correct_result_sha_256_raw),
                                                .funct = vscf_iotelic_sha256_hash};

static const uint8_t correct_result_sha_384_raw[] = {
        0x61, 0xf0, 0xbb, 0x30, 0xa9, 0xca, 0x9a, 0xec, 0x94, 0x21, 0xb5, 0xfb, 0xe2, 0x98, 0x0d, 0x60,
        0xf2, 0xe3, 0x35, 0x70, 0x8b, 0xf2, 0x14, 0x4b, 0x85, 0x9f, 0xdb, 0x3e, 0xa0, 0xbf, 0x46, 0x2a,
        0x6f, 0x5b, 0xc2, 0x1a, 0x44, 0xf7, 0x7c, 0xf2, 0x3b, 0x47, 0xe0, 0x56, 0x27, 0xb9, 0xa5, 0x7b};
static const vs_test_data_t sha384_test_data = {.correct_result_raw = correct_result_sha_384_raw,
                                                .correct_result_size = sizeof(correct_result_sha_384_raw),
                                                .funct = vscf_iotelic_sha384_hash};

static const uint8_t correct_result_sha_512_raw[] = {
        0xe7, 0x3c, 0xa0, 0x66, 0xc1, 0x1f, 0x56, 0xf5, 0xd8, 0x35, 0x93, 0x2b, 0xaa, 0xdd, 0xbf, 0x71,
        0x0a, 0xb2, 0xbd, 0x1b, 0x51, 0x86, 0xf3, 0x2b, 0x5b, 0xdf, 0xaf, 0x20, 0x50, 0xfe, 0xeb, 0x13,
        0x39, 0x17, 0xb1, 0x58, 0xf7, 0x51, 0x4f, 0xd4, 0x61, 0x2e, 0x75, 0xe7, 0x74, 0x8f, 0x59, 0x2a,
        0x80, 0xde, 0x87, 0x50, 0x7c, 0x21, 0xae, 0x72, 0x34, 0x16, 0x9f, 0x89, 0x41, 0x1c, 0x34, 0xda};
static const vs_test_data_t sha512_test_data = {.correct_result_raw = correct_result_sha_512_raw,
                                                .correct_result_size = sizeof(correct_result_sha_512_raw),
                                                .funct = vscf_iotelic_sha512_hash};

/******************************************************************************/
void
test_hash(void) {
    START_TEST("HASH tests");

    TEST_CASE_OK("SHA256 pass", _test_sha_pass(&sha256_test_data));
    TEST_CASE_OK("SHA384 pass", _test_sha_pass(&sha384_test_data));
    TEST_CASE_OK("SHA512 pass", _test_sha_pass(&sha512_test_data));

terminate:;
}