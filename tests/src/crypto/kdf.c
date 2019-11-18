
#include <virgil/iot/tests/helpers.h>
#include <private/private_helpers.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

static const char key_raw[] = "Test data for kdf2";
static const char another_key_raw[] = "Another test data for kdf2";

static const char *hkdf_input = "Test input";
static const char *another_hkdf_input = "Another test input";
static const char *hkdf_salt = "Test salt";
static const char *another_hkdf_salt = "Another test salt";
static const char *hkdf_info = "Test info";
static const char *another_hkdf_info = "Another test info";

/******************************************************************************/
static int
_test_kdf2_step(vs_secmodule_impl_t *secmodule_impl,
                vs_secmodule_hash_type_e hash_type,
                const uint8_t *correct_result,
                uint16_t result_len) {
    uint8_t result_buf[result_len];
    uint8_t another_result_buf[result_len];
    int res;

    res = secmodule_impl->kdf(VS_KDF_2, hash_type, (uint8_t *)key_raw, VS_IOT_STRLEN(key_raw), result_buf, result_len);
    CHECK_RET(VS_CODE_ERR_NOT_IMPLEMENTED != res, res, "");
    CHECK_RET(VS_CODE_OK == res, res, "ERROR while execute kdf");

    CHECK_RET(0 == VS_IOT_MEMCMP(result_buf, correct_result, result_len), VS_CODE_ERR_CRYPTO, "kdf is wrong");

    res = secmodule_impl->kdf(VS_KDF_2,
                              hash_type,
                              (uint8_t *)another_key_raw,
                              VS_IOT_STRLEN(another_key_raw),
                              another_result_buf,
                              result_len);
    CHECK_RET(VS_CODE_OK == res, res, "ERROR while execute kdf");

    CHECK_RET(
            0 != VS_IOT_MEMCMP(another_result_buf, correct_result, result_len), VS_CODE_ERR_CRYPTO, "kdf is constant");
    return res;
}

/******************************************************************************/
static int
_test_hkdf2_step(vs_secmodule_impl_t *secmodule_impl,
                 vs_secmodule_hash_type_e hash_type,
                 const uint8_t *correct_result,
                 uint16_t result_len) {
    uint8_t result_buf[result_len];
    int res;
    VS_IOT_MEMSET(result_buf, 0, result_len);

    res = secmodule_impl->hkdf(hash_type,
                               (uint8_t *)hkdf_input,
                               VS_IOT_STRLEN(hkdf_input),
                               (uint8_t *)hkdf_salt,
                               VS_IOT_STRLEN(hkdf_salt),
                               (uint8_t *)hkdf_info,
                               VS_IOT_STRLEN(hkdf_info),
                               result_buf,
                               result_len);
    CHECK_RET(VS_CODE_ERR_NOT_IMPLEMENTED != res, res, "");
    CHECK_RET(VS_CODE_OK == res, res, "ERROR while execute hkdf");

    CHECK_RET(0 == VS_IOT_MEMCMP(result_buf, correct_result, result_len), VS_CODE_ERR_CRYPTO, "hkdf is wrong");

    VS_IOT_MEMSET(result_buf, 0, result_len);

    res = secmodule_impl->hkdf(hash_type,
                               (uint8_t *)hkdf_input,
                               VS_IOT_STRLEN(hkdf_input),
                               (uint8_t *)another_hkdf_salt,
                               VS_IOT_STRLEN(another_hkdf_salt),
                               (uint8_t *)hkdf_info,
                               VS_IOT_STRLEN(hkdf_info),
                               result_buf,
                               result_len);
    CHECK_RET(VS_CODE_OK == res, res, "ERROR while execute hkdf");

    CHECK_RET(0 != VS_IOT_MEMCMP(result_buf, correct_result, result_len),
              VS_CODE_ERR_CRYPTO,
              "Same hkdf with other salt");

    VS_IOT_MEMSET(result_buf, 0, result_len);
    res = secmodule_impl->hkdf(hash_type,
                               (uint8_t *)another_hkdf_input,
                               VS_IOT_STRLEN(another_hkdf_input),
                               (uint8_t *)hkdf_salt,
                               VS_IOT_STRLEN(hkdf_salt),
                               (uint8_t *)hkdf_info,
                               VS_IOT_STRLEN(hkdf_info),
                               result_buf,
                               result_len);
    CHECK_RET(VS_CODE_OK == res, res, "ERROR while execute hkdf");
    CHECK_RET(0 != VS_IOT_MEMCMP(result_buf, correct_result, result_len),
              VS_CODE_ERR_CRYPTO,
              "Same hkdf with other input");

    VS_IOT_MEMSET(result_buf, 0, result_len);
    res = secmodule_impl->hkdf(hash_type,
                               (uint8_t *)hkdf_input,
                               VS_IOT_STRLEN(hkdf_input),
                               (uint8_t *)hkdf_salt,
                               VS_IOT_STRLEN(hkdf_salt),
                               (uint8_t *)another_hkdf_info,
                               VS_IOT_STRLEN(another_hkdf_info),
                               result_buf,
                               result_len);
    CHECK_RET(VS_CODE_OK == res, res, "ERROR while execute hkdf");

    CHECK_RET(0 != VS_IOT_MEMCMP(result_buf, correct_result, result_len),
              VS_CODE_ERR_CRYPTO,
              "Same hkdf with other info");

    return res;
}

/******************************************************************************/
uint16_t
test_kdf2(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;

#define TEST_STEP(COND, BITLEN, FUNC)                                                                                  \
    do {                                                                                                               \
        int res = COND;                                                                                                \
        if (VS_CODE_ERR_NOT_IMPLEMENTED == res) {                                                                      \
            VS_LOG_WARNING(#FUNC " for SHA_" #BITLEN " algorithm is not implemented");                                 \
        } else {                                                                                                       \
            TEST_CASE_OK(vs_secmodule_hash_type_descr(VS_HASH_SHA_##BITLEN), VS_CODE_OK == res);                       \
        }                                                                                                              \
    } while (0)

    static const uint8_t sha256_result_raw[] = {
            0x85, 0xc0, 0x97, 0xf6, 0x09, 0xfb, 0x8c, 0x9b, 0xe6, 0xc4, 0xfa, 0xf1, 0x10, 0xde, 0xb6, 0xcf,
            0x9a, 0xda, 0xb0, 0xe4, 0x8a, 0x34, 0x50, 0xad, 0x96, 0xcc, 0xb0, 0x7a, 0xd1, 0x78, 0xed, 0xcc,
            0xca, 0x0d, 0x37, 0xfa, 0xc6, 0xba, 0x17, 0x35, 0x2a, 0xcf, 0xb6, 0x38, 0x2b, 0xe4, 0x45, 0xff,
            0xc7, 0x57, 0x15, 0x41, 0x38, 0x66, 0x34, 0xef, 0xb5, 0x5c, 0x7b, 0x06, 0x0a, 0x85, 0x22, 0xfc,
            0x98, 0x30, 0x26, 0x55, 0x71, 0xdd, 0x57, 0xb1, 0xbd, 0x72, 0xdc, 0xf4, 0x9d, 0xb5, 0xa4, 0xb7,
            0xd7, 0x22, 0x12, 0x19, 0x92, 0x59, 0x87, 0x07, 0xf1, 0x59, 0x0e, 0x1f, 0x0f, 0x3f, 0x99, 0x8e};

    static const uint8_t sha384_result_raw[] = {
            0xf8, 0xcb, 0x2b, 0x97, 0x55, 0xbd, 0xae, 0xdb, 0xb4, 0xcf, 0x97, 0x36, 0x00, 0xb9, 0x2f, 0x13,
            0x49, 0xd9, 0x9d, 0xd3, 0x79, 0x09, 0x92, 0x78, 0x38, 0x55, 0x77, 0x35, 0x22, 0x55, 0x82, 0x53,
            0x4b, 0xc0, 0x85, 0x40, 0xf1, 0xad, 0x73, 0x50, 0x4d, 0x71, 0x7f, 0x79, 0x99, 0x1c, 0x36, 0x63,
            0x0a, 0x81, 0xbc, 0x72, 0x58, 0x52, 0x35, 0xc9, 0xbb, 0x3d, 0xda, 0x11, 0x26, 0xc4, 0xee, 0xd2,
            0x51, 0xf7, 0x78, 0x33, 0xfd, 0x28, 0xdc, 0xca, 0x6d, 0x80, 0xa5, 0xea, 0x7f, 0x8d, 0xe1, 0xd1,
            0xde, 0x90, 0x78, 0xa3, 0x00, 0xf3, 0xa4, 0xb3, 0x7a, 0x70, 0x57, 0x97, 0xd0, 0x5d, 0xd6, 0xb9};

    static const uint8_t sha512_result_raw[] = {
            0xfe, 0x4f, 0xc9, 0x6e, 0xc9, 0x31, 0xde, 0x14, 0x3d, 0xec, 0x5f, 0x73, 0x5e, 0xae, 0xe3, 0xd4,
            0xb0, 0x62, 0xc8, 0x29, 0x9f, 0x45, 0xe8, 0xb9, 0xea, 0xaf, 0xed, 0xe7, 0x5e, 0x33, 0x2a, 0x91,
            0x97, 0x01, 0x4b, 0x31, 0x7d, 0xfb, 0x2e, 0xed, 0x75, 0x27, 0x68, 0xa3, 0xc2, 0xb4, 0x25, 0xa4,
            0xee, 0x9b, 0x1f, 0x53, 0xcb, 0x16, 0x22, 0x51, 0x53, 0x28, 0x2c, 0x28, 0xd7, 0xcb, 0xb8, 0xfc,
            0x2c, 0xab, 0xc7, 0x95, 0x1e, 0xb0, 0x6c, 0x39, 0x6b, 0x5b, 0xda, 0x0d, 0x42, 0x17, 0xab, 0x03,
            0x51, 0xc8, 0x15, 0x48, 0x68, 0x9c, 0xbc, 0x23, 0x91, 0xe6, 0x8a, 0xf2, 0x2c, 0xb2, 0x96, 0xc2};

    static const uint8_t hkdf384_result_raw[] = {
            0x8c, 0xf1, 0x41, 0x94, 0x81, 0x14, 0x74, 0xd0, 0xe7, 0x62, 0x6c, 0x86, 0x2f, 0xf8, 0xb1, 0x31,
            0x5c, 0xe8, 0xc4, 0xb9, 0x68, 0xb6, 0x80, 0x27, 0xc1, 0xb7, 0xdd, 0xfd, 0x5b, 0x94, 0xe9, 0x15,
            0x13, 0x9d, 0x3e, 0x86, 0xf1, 0xd6, 0xac, 0xf6, 0xa2, 0xc1, 0x93, 0xa2, 0x6c, 0x4c, 0x2f, 0xb0,
            0xd7, 0xd8, 0x6a, 0xb3, 0x76, 0xc8, 0x25, 0x29, 0x8f, 0x87, 0x58, 0xb7, 0x43, 0xa9, 0xde, 0x8b,
            0x1d, 0xd1, 0x9e, 0x51, 0xa2, 0x09, 0x26, 0xe2, 0x8f, 0xb7, 0x94, 0x52, 0x43, 0x77, 0x5c, 0x28,
            0x9a, 0x43, 0x43, 0x03, 0x14, 0xa5, 0x6a, 0x3d, 0x38, 0x03, 0x26, 0xe8, 0xd9, 0xe5, 0xfe, 0x34,
            0xab, 0xb2, 0x6e, 0x4f, 0x71, 0x0e, 0x9f, 0xd9, 0x7a, 0x34, 0xd8, 0x3d, 0x8f, 0xf0, 0xde, 0xe4,
            0xf9, 0x2a, 0x2d, 0xa4, 0x3b, 0x80, 0x51, 0x95, 0x00, 0xcd, 0xef, 0xbf, 0x35, 0x7c, 0x63, 0x53};
    START_TEST("KDF2 tests");

    TEST_STEP(
            _test_kdf2_step(secmodule_impl, VS_HASH_SHA_256, sha256_result_raw, sizeof(sha256_result_raw)), 256, "KDF");
    TEST_STEP(
            _test_kdf2_step(secmodule_impl, VS_HASH_SHA_384, sha384_result_raw, sizeof(sha256_result_raw)), 384, "KDF");
    TEST_STEP(
            _test_kdf2_step(secmodule_impl, VS_HASH_SHA_512, sha512_result_raw, sizeof(sha256_result_raw)), 512, "KDF");

    START_TEST("HKDF tests");

    TEST_STEP(_test_hkdf2_step(secmodule_impl, VS_HASH_SHA_384, hkdf384_result_raw, sizeof(hkdf384_result_raw)),
              384,
              "HKDF");

terminate:
    return failed_test_result;

#undef TEST_STEP
}
