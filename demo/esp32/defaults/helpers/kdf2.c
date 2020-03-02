#include <stdlib.h>
#include <stdint.h>

#include "mbedtls/md.h"
#include <virgil/iot/status_code/status_code.h>

#define KDF2_TRY(invocation)                                                                                           \
    do {                                                                                                               \
        result = invocation;                                                                                           \
        if ((result) < 0) {                                                                                            \
            goto exit;                                                                                                 \
        }                                                                                                              \
    } while (0)

#define KDF2_CEIL(x, y) (1 + ((x - 1) / y))

/********************************************************************************/
vs_status_e
vs_mbedtls_kdf2(const mbedtls_md_info_t *md_info,
                const unsigned char *input,
                size_t ilen,
                unsigned char *output,
                size_t olen) {
    int result = 0;
    size_t counter = 1;
    size_t counter_len = 0;
    unsigned char counter_string[4] = {0x0};

    unsigned char hash[MBEDTLS_MD_MAX_SIZE] = {0x0};
    unsigned char hash_len = 0;

    size_t olen_actual = 0;

    mbedtls_md_context_t md_ctx;

    CHECK_NOT_ZERO_RET(md_info, VS_CODE_ERR_CRYPTO);

    // Initialize digest context
    mbedtls_md_init(&md_ctx);
    KDF2_TRY(mbedtls_md_setup(&md_ctx, md_info, 0));

    // Get hash parameters
    hash_len = mbedtls_md_get_size(md_info);

    // Get KDF parameters
    counter_len = KDF2_CEIL(olen, hash_len);

    // Start hashing
    for (; counter <= counter_len; ++counter) {
        counter_string[0] = (unsigned char)((counter >> 24) & 255);
        counter_string[1] = (unsigned char)((counter >> 16) & 255);
        counter_string[2] = (unsigned char)((counter >> 8)) & 255;
        counter_string[3] = (unsigned char)(counter & 255);
        KDF2_TRY(mbedtls_md_starts(&md_ctx));
        KDF2_TRY(mbedtls_md_update(&md_ctx, input, ilen));
        KDF2_TRY(mbedtls_md_update(&md_ctx, counter_string, 4));
        if (olen_actual + hash_len <= olen) {
            KDF2_TRY(mbedtls_md_finish(&md_ctx, output + olen_actual));
            olen_actual += hash_len;
        } else {
            KDF2_TRY(mbedtls_md_finish(&md_ctx, hash));
            memcpy(output + olen_actual, hash, olen - olen_actual);
            olen_actual = olen;
        }
    }
exit:
    mbedtls_md_free(&md_ctx);
    return (0 == result) ? VS_CODE_OK : VS_CODE_ERR_CRYPTO;
}
