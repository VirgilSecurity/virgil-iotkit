#include <stdlib.h>

#include <global-hal.h>
#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/hsm/hsm_interface.h>

#define TEST_FILENAME_LITTLE_DATA "test_little_file"
#define TEST_FILENAME_BIG_DATA "test_big_file"
#define TEST_FILENAME_FOR_DELETE "test_delete_file"

static const char _little_test_data[] = "Little string for test";

/******************************************************************************/
static bool
_test_case_secbox_save_load(vs_storage_op_ctx_t *ctx,
                            const char *filename,
                            vs_secbox_type_t type,
                            const char *test_data,
                            uint32_t data_sz) {

    uint8_t buf[data_sz];
    uint16_t hash_sz;
    vs_storage_element_id_t file_id;

    vs_hsm_hash_create(VS_HASH_SHA_256, (uint8_t *)filename, strlen(filename), file_id, sizeof(file_id), &hash_sz);

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_secbox_save(ctx, type, file_id, (uint8_t *)test_data, data_sz),
                   "Error save file")

    BOOL_CHECK_RET(data_sz == vs_secbox_file_size(ctx, file_id), "Error file size")

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_secbox_load(ctx, file_id, buf, data_sz), "Error read file")
    MEMCMP_CHECK_RET(buf, test_data, data_sz)

    return true;
}

/******************************************************************************/
static bool
_test_case_secbox_del(vs_storage_op_ctx_t *ctx, const char *filename) {

    char buf[] = "test data";
    uint16_t hash_sz;
    vs_storage_element_id_t file_id;

    vs_hsm_hash_create(VS_HASH_SHA_256, (uint8_t *)filename, strlen(filename), file_id, sizeof(file_id), &hash_sz);

    BOOL_CHECK_RET(_test_case_secbox_save_load(ctx, filename, VS_SECBOX_SIGNED, buf, strlen(buf)),
                   "Error create file for delete test")

    BOOL_CHECK_RET(VS_STORAGE_OK == vs_secbox_del(ctx, file_id), "Error delete file")

    BOOL_CHECK_RET(0 > vs_secbox_file_size(ctx, file_id), "File is not deleted")

    return true;
}

/**********************************************************/
uint16_t
vs_secbox_test(vs_storage_op_ctx_t *ctx) {
    uint16_t failed_test_result = 0;
    char *_big_test_data = NULL;
    START_TEST("Secbox tests");

    if (NULL == ctx) {
        RESULT_ERROR;
    }

    TEST_CASE_OK("Init secbox", VS_STORAGE_OK == vs_secbox_init(ctx))

    TEST_CASE_OK(
            "Read/write small piece of data. Signed only",
            _test_case_secbox_save_load(
                    ctx, TEST_FILENAME_LITTLE_DATA, VS_SECBOX_SIGNED, _little_test_data, sizeof(_little_test_data)))

    size_t big_test_size = (ctx->file_sz_limit > (3 * 256 + 128 - 1)) ? 3 * 256 + 128 - 1 : ctx->file_sz_limit;
    _big_test_data = VS_IOT_MALLOC(big_test_size);
    for (uint32_t i = 0; i < big_test_size; i++) {
        _big_test_data[i] = (uint8_t)i;
    }

    TEST_CASE_OK(
            "Read/write big piece of data. Signed only",
            _test_case_secbox_save_load(ctx, TEST_FILENAME_BIG_DATA, VS_SECBOX_SIGNED, _big_test_data, big_test_size))

    TEST_CASE_OK("Delete file", _test_case_secbox_del(ctx, TEST_FILENAME_FOR_DELETE))

    TEST_CASE_OK("Read/write small piece of data. Signed and encrypted",
                 _test_case_secbox_save_load(ctx,
                                             TEST_FILENAME_LITTLE_DATA,
                                             VS_SECBOX_SIGNED_AND_ENCRYPTED,
                                             _little_test_data,
                                             sizeof(_little_test_data)))

    TEST_CASE_OK("Read/write big piece of data.Signed and encrypted",
                 _test_case_secbox_save_load(
                         ctx, TEST_FILENAME_BIG_DATA, VS_SECBOX_SIGNED_AND_ENCRYPTED, _big_test_data, big_test_size))
terminate:;
    if (_big_test_data) {
        VS_IOT_FREE(_big_test_data);
    }
    vs_secbox_deinit(ctx);
    return failed_test_result;
}
