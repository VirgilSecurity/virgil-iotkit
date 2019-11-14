
#include <virgil/iot/tests/helpers.h>
#include <private/private_helpers.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

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


static const uint8_t long_test_data[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x04, 0x91, 0xF7,
                                         0x62, 0x91, 0x45, 0x5A, 0x58, 0xA6, 0xD5, 0x5C, 0x5D, 0x06, 0x82, 0x99, 0x77,
                                         0xF2, 0x73, 0x4B, 0x99, 0x28, 0x44, 0x76, 0x9A, 0xFC, 0xB4, 0x08, 0x52, 0x8C,
                                         0x87, 0xA5, 0xA6, 0x30, 0xFF, 0x75, 0xE5, 0x4A, 0x2E, 0xD0, 0x95, 0x8D, 0xC2,
                                         0x4A, 0xA4, 0x46, 0x80, 0x4E, 0x05, 0xF5, 0x59, 0x14, 0xC2, 0xBE, 0x10, 0x5E,
                                         0x30, 0x47, 0x8C, 0x4B, 0x0F, 0xFA, 0x90, 0x90, 0x7D, 0x22};

static const uint8_t long_sha256_hash[] = {0x47, 0x79, 0x98, 0xCB, 0x39, 0xC5, 0x4E, 0x44, 0x35, 0xCD, 0x69,
                                           0x1C, 0xD4, 0x5D, 0xDD, 0xB2, 0x40, 0x41, 0xA3, 0xF8, 0xD3, 0xB3,
                                           0xD5, 0x85, 0x06, 0x0E, 0x68, 0x87, 0x37, 0x32, 0xA2, 0xDE};


/******************************************************************************/
static bool
_test_long_sha_pass(vs_secmodule_impl_t *secmodule_impl,
                    vs_secmodule_hash_type_e hash_type,
                    const uint8_t *data,
                    uint16_t data_sz,
                    const uint8_t *ref_result,
                    uint16_t ref_result_size) {
    static uint8_t result_buf[HASH_MAX_BUF_SIZE];
    uint16_t result_sz;

    BOOL_CHECK_RET(VS_CODE_OK ==
                           secmodule_impl->hash(hash_type, data, data_sz, result_buf, sizeof(result_buf), &result_sz),
                   "Error execute hash op");
    BOOL_CHECK_RET(result_sz == ref_result_size, "Incorrect size of result");

    MEMCMP_CHECK_RET(ref_result, result_buf, result_sz, false);

    return true;
}

/******************************************************************************/
static bool
_test_sha_pass(vs_secmodule_impl_t *secmodule_impl,
               vs_secmodule_hash_type_e hash_type,
               const uint8_t *correct_result_raw,
               uint16_t correct_result_size) {
    static uint8_t result_buf[HASH_MAX_BUF_SIZE];
    static uint8_t another_result_buf[HASH_MAX_BUF_SIZE];
    uint16_t result_sz;

    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->hash(hash_type,
                                                      (uint8_t *)test_data,
                                                      VS_IOT_STRLEN(test_data),
                                                      result_buf,
                                                      sizeof(result_buf),
                                                      &result_sz),
                   "Error execute hash op");
    BOOL_CHECK_RET(result_sz == correct_result_size, "Incorrect size of result");

    MEMCMP_CHECK_RET(correct_result_raw, result_buf, result_sz, false);

    BOOL_CHECK_RET(VS_CODE_OK == secmodule_impl->hash(hash_type,
                                                      (uint8_t *)another_test_data,
                                                      VS_IOT_STRLEN(another_test_data),
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
_test_partial_sha_pass(vs_secmodule_impl_t *secmodule_impl,
                       vs_secmodule_hash_type_e hash_type,
                       const uint8_t *correct_result_raw,
                       uint16_t correct_result_size) {

    switch (hash_type) {
    case VS_HASH_SHA_256: {
        vs_secmodule_sw_sha256_ctx ctx;
        static uint8_t result_buf[SHA256_SIZE];
        static uint8_t another_result_buf[SHA256_SIZE];

        secmodule_impl->hash_init(&ctx);
        secmodule_impl->hash_update(&ctx, (uint8_t *)test_data, VS_IOT_STRLEN(test_data));
        secmodule_impl->hash_finish(&ctx, result_buf);

        MEMCMP_CHECK_RET(correct_result_raw, result_buf, sizeof(result_buf), false);

        secmodule_impl->hash_init(&ctx);
        secmodule_impl->hash_update(&ctx, (uint8_t *)another_test_data, VS_IOT_STRLEN(another_test_data));
        secmodule_impl->hash_finish(&ctx, another_result_buf);

        BOOL_CHECK_RET(0 != memcmp(correct_result_raw, another_result_buf, sizeof(another_result_buf)),
                       "Hash is constant");
    } break;
    default:
        return false;
    }

    return true;
}

#define TEST_STEP(BITLEN)                                                                                              \
    do {                                                                                                               \
        vs_secmodule_hash_type_e hash_type = VS_HASH_SHA_##BITLEN;                                                     \
        const uint8_t *correct_result_raw = correct_result_sha_##BITLEN##_raw;                                         \
        uint16_t correct_result_size = sizeof(correct_result_sha_##BITLEN##_raw);                                      \
                                                                                                                       \
        TEST_HASH_NOT_IMPLEMENTED(hash_type);                                                                          \
                                                                                                                       \
        if (not_implemented) {                                                                                         \
            VS_LOG_WARNING("Hash for SHA_" #BITLEN " algorithm is not implemented");                                   \
        } else {                                                                                                       \
            TEST_CASE_OK(vs_secmodule_hash_type_descr(hash_type),                                                      \
                         _test_sha_pass(secmodule_impl, hash_type, correct_result_raw, correct_result_size));          \
        }                                                                                                              \
    } while (0)

/******************************************************************************/
uint16_t
test_hash(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;
    bool not_implemented = false;

    VS_IOT_ASSERT(secmodule_impl);
    CHECK_NOT_ZERO_RET(secmodule_impl, 1);

    START_TEST("HASH tests");

    TEST_CASE_OK(vs_secmodule_hash_type_descr(VS_HASH_SHA_256),
                 _test_long_sha_pass(secmodule_impl,
                                     VS_HASH_SHA_256,
                                     long_test_data,
                                     sizeof(long_test_data),
                                     long_sha256_hash,
                                     sizeof(long_sha256_hash)));

    TEST_STEP(256);

    if (!not_implemented) {
        TEST_CASE_OK("SHA256 partial calculating pass",
                     _test_partial_sha_pass(secmodule_impl,
                                            VS_HASH_SHA_256,
                                            correct_result_sha_256_raw,
                                            sizeof(correct_result_sha_256_raw)));
    }

    TEST_STEP(384);
    TEST_STEP(512);

terminate:
    return failed_test_result;

#undef TEST_STEP
}