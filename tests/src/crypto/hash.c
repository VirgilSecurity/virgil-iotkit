
#include <helpers.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_sw_sha2_routines.h>


static const char *test_data = "Data for hash creation ...";
static const char *another_test_data = "Another data for hash creation ...";

static const uint8_t correct_result_sha_256_raw[] = {0xef, 0x25, 0x84, 0xbc, 0x6f, 0xaf, 0x4a, 0x77, 0xff, 0x32, 0xe7,
                                                     0x45, 0x82, 0x62, 0xef, 0x89, 0x08, 0x8e, 0x93, 0x88, 0x64, 0x67,
                                                     0xa2, 0xc8, 0x19, 0xbd, 0x99, 0x60, 0xb8, 0x6e, 0xfb, 0x16};

static const uint8_t correct_result_sha_384_raw[] = {
        0x61, 0xf0, 0xbb, 0x30, 0xa9, 0xca, 0x9a, 0xec, 0x94, 0x21, 0xb5, 0xfb, 0xe2, 0x98, 0x0d, 0x60,
        0xf2, 0xe3, 0x35, 0x70, 0x8b, 0xf2, 0x14, 0x4b, 0x85, 0x9f, 0xdb, 0x3e, 0xa0, 0xbf, 0x46, 0x2a,
        0x6f, 0x5b, 0xc2, 0x1a, 0x44, 0xf7, 0x7c, 0xf2, 0x3b, 0x47, 0xe0, 0x56, 0x27, 0xb9, 0xa5, 0x7b};

static const uint8_t correct_result_sha_512_raw[] = {
        0xe7, 0x3c, 0xa0, 0x66, 0xc1, 0x1f, 0x56, 0xf5, 0xd8, 0x35, 0x93, 0x2b, 0xaa, 0xdd, 0xbf, 0x71,
        0x0a, 0xb2, 0xbd, 0x1b, 0x51, 0x86, 0xf3, 0x2b, 0x5b, 0xdf, 0xaf, 0x20, 0x50, 0xfe, 0xeb, 0x13,
        0x39, 0x17, 0xb1, 0x58, 0xf7, 0x51, 0x4f, 0xd4, 0x61, 0x2e, 0x75, 0xe7, 0x74, 0x8f, 0x59, 0x2a,
        0x80, 0xde, 0x87, 0x50, 0x7c, 0x21, 0xae, 0x72, 0x34, 0x16, 0x9f, 0x89, 0x41, 0x1c, 0x34, 0xda};

/******************************************************************************/
static bool
_test_sha_pass(vs_hsm_hash_type hash_type, const uint8_t *correct_result_raw, size_t correct_result_size) {
    static uint8_t result_buf[64];
    static uint8_t another_result_buf[64];
    uint16_t result_sz;

    BOOL_CHECK_RET(0 == vs_hsm_hash_create(hash_type,
                                           (uint8_t *)test_data,
                                           strlen(test_data),
                                           result_buf,
                                           sizeof(result_buf),
                                           &result_sz),
                   "Error execute hash op");
    BOOL_CHECK_RET(result_sz == correct_result_size, "Incorrect size of result")

    MEMCMP_CHECK_RET(correct_result_raw, result_buf, result_sz);

    BOOL_CHECK_RET(0 == vs_hsm_hash_create(hash_type,
                                           (uint8_t *)another_test_data,
                                           strlen(another_test_data),
                                           another_result_buf,
                                           sizeof(another_result_buf),
                                           &result_sz),
                   "Error execute hash op");
    BOOL_CHECK_RET(result_sz == correct_result_size, "Incorrect size of result");
    BOOL_CHECK_RET(0 != memcmp(correct_result_raw, another_result_buf, result_sz), "Hash is constant");

    return true;
}

/******************************************************************************/
static bool
_test_partial_sha_pass(vs_hsm_hash_type hash_type, const uint8_t *correct_result_raw, size_t correct_result_size) {

    switch (hash_type) {
    case VS_HASH_SHA_256: {
        vs_hsm_sw_sha256_ctx ctx;
        static uint8_t result_buf[32];
        static uint8_t another_result_buf[32];

        vs_hsm_sw_sha256_init(&ctx);
        vs_hsm_sw_sha256_update(&ctx, (uint8_t *)test_data, strlen(test_data));
        vs_hsm_sw_sha256_final(&ctx, result_buf);

        MEMCMP_CHECK_RET(correct_result_raw, result_buf, sizeof(result_buf));

        vs_hsm_sw_sha256_init(&ctx);
        vs_hsm_sw_sha256_update(&ctx, (uint8_t *)another_test_data, strlen(another_test_data));
        vs_hsm_sw_sha256_final(&ctx, another_result_buf);

        BOOL_CHECK_RET(0 != memcmp(correct_result_raw, another_result_buf, sizeof(another_result_buf)),
                       "Hash is constant");
    } break;
    default:
        return false;
    }

    return true;
}

/******************************************************************************/
void
test_hash(void) {

    START_TEST("HASH tests");

    TEST_CASE_OK("SHA256 pass",
                 _test_sha_pass(VS_HASH_SHA_256, correct_result_sha_256_raw, sizeof(correct_result_sha_256_raw)));
    TEST_CASE_OK("SHA384 pass",
                 _test_sha_pass(VS_HASH_SHA_384, correct_result_sha_384_raw, sizeof(correct_result_sha_384_raw)));
    TEST_CASE_OK("SHA512 pass",
                 _test_sha_pass(VS_HASH_SHA_512, correct_result_sha_512_raw, sizeof(correct_result_sha_512_raw)));
    TEST_CASE_OK(
            "SHA256 partial calculating pass",
            _test_partial_sha_pass(VS_HASH_SHA_256, correct_result_sha_256_raw, sizeof(correct_result_sha_256_raw)));

terminate:;
}