#include <stdlib.h>
#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/macros/macros.h>

#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/hsm/hsm_interface.h>

#define TEST_FILENAME_LITTLE_DATA "test_little_file"
#define TEST_FILENAME_BIG_DATA "test_big_file"

static const char _little_test_data[] = "Little string for test";

/******************************************************************************/
static bool
_test_case_secbox_save_load(vs_storage_op_ctx_t *ctx, const char *filename, const char *test_data, uint32_t data_sz) {

    uint8_t buf[data_sz];
    uint16_t hash_sz;
    vs_storage_element_id_t file_id;

    vs_hsm_hash_create(VS_HASH_SHA_256, (uint8_t *)filename, strlen(filename), file_id, sizeof(file_id), &hash_sz);

    BOOL_CHECK_RET(0 == vs_secbox_save(ctx, VS_SECBOX_SIGNED, file_id, (uint8_t *)test_data, data_sz),
                   "Error save file")

    BOOL_CHECK_RET(data_sz == vs_secbox_load(ctx, file_id, buf, data_sz), "Error read file")
    MEMCMP_CHECK_RET(buf, test_data, data_sz)

    return true;
}

/**********************************************************/
void
vs_secbox_test(vs_storage_op_ctx_t *ctx) {
    char *_big_test_data = NULL;
    START_TEST("Secbox tests");

    if (NULL == ctx) {
        RESULT_ERROR;
    }

    TEST_CASE_OK("Init secbox", VS_STORAGE_OK == vs_secbox_init(ctx))

    TEST_CASE_OK(
            "Read/write small piece of data",
            _test_case_secbox_save_load(ctx, TEST_FILENAME_LITTLE_DATA, _little_test_data, sizeof(_little_test_data)))

    size_t big_test_size = (ctx->file_sz_limit > (3 * 256 + 128 - 1)) ? 3 * 256 + 128 - 1 : ctx->file_sz_limit;
    _big_test_data = VS_IOT_MALLOC(big_test_size);
    for (uint32_t i = 0; i < big_test_size; i++) {
        _big_test_data[i] = (uint8_t)i;
    }

    TEST_CASE_OK("Read/write big piece of data",
                 _test_case_secbox_save_load(ctx, TEST_FILENAME_BIG_DATA, _big_test_data, sizeof(_big_test_data)))
terminate:;
    if (_big_test_data) {
        VS_IOT_FREE(_big_test_data);
    }
    vs_secbox_deinit(ctx);
}
