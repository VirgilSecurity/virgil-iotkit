//
// Created by Maxim Grigoryev on 2019-06-21.
//

#ifndef VS_CRYPTO_CONVERTERS_MACROS_H
#define VS_CRYPTO_CONVERTERS_MACROS_H

#include <stdbool.h>

#define ASN1_CHK_ADD(g, f)                                                                                             \
    do {                                                                                                               \
        if ((res_sz = f) < 0)                                                                                          \
            return (false);                                                                                            \
        else                                                                                                           \
            g += res_sz;                                                                                               \
    } while (0)

#define NOT_ZERO(VAL)                                                                                                  \
    do {                                                                                                               \
        if (!(VAL)) {                                                                                                  \
            return -1;                                                                                                 \
        }                                                                                                              \
    } while (0)

#define MBEDTLS_CHECK(COMMAND, RESCODE)                                                                                \
    do {                                                                                                               \
        mbedtls_res = (COMMAND);                                                                                       \
        if (mbedtls_res < 0) {                                                                                         \
            res = (RESCODE);                                                                                           \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

#define CHECK_BOOL_GOTO(VAL, RESCODE)                                                                                  \
    do {                                                                                                               \
        if (!(VAL)) {                                                                                                  \
            res = RESCODE;                                                                                             \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)


#endif // VS_CRYPTO_CONVERTERS_MACROS_H
