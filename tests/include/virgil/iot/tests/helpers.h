//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#ifndef VS_IOT_SDK_TESTS_HELPERS_H_
#define VS_IOT_SDK_TESTS_HELPERS_H_

#include <stdbool.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>

#define VS_HSM_CHECK_IS_NOT_IMPLEMENTED(OPERATION, MESSAGE, ...)                                                       \
    do {                                                                                                               \
        if (VS_HSM_ERR_NOT_IMPLEMENTED == (OPERATION)) {                                                               \
            VS_LOG_WARNING(MESSAGE, ##__VA_ARGS__);                                                                    \
            return true;                                                                                               \
        }                                                                                                              \
    } while (0)

#define VS_HSM_CHECK_RET(OPERATION, MESSAGE, ...) BOOL_CHECK_RET(VS_HSM_ERR_OK == (OPERATION), MESSAGE, ##__VA_ARGS__)

#define CHECK_GOTO(OPERATION, DESCRIPTION, ...) do {                                                                       \
    if (!(OPERATION)) {                                                                                                \
        VS_LOG_ERROR(DESCRIPTION, ##__VA_ARGS__);                                                                      \
        goto terminate;                                                                                                \
    } } while(0)

#define RESULT_BUF_SIZE (1024)
#define HASH_MAX_BUF_SIZE (64)
#define SHA256_SIZE (32)
#define PUBKEY_MAX_BUF_SIZE (256)

#define BORDER VS_LOG_INFO("------------------------------------------------------");

#define START_TESTS                                                                                                    \
    do {                                                                                                               \
        BORDER;                                                                                                        \
        VS_LOG_INFO("[TESTS-BEGIN]");                                                                                  \
    } while (0)

#define FINISH_TESTS                                                                                                   \
    do {                                                                                                               \
        BORDER;                                                                                                        \
        VS_LOG_INFO("[TESTS-END]");                                                                                    \
        if (failed_test_result == 0) {                                                                                 \
            VS_LOG_INFO("Test have been finished successfully");                                                       \
        } else if (failed_test_result == 1) {                                                                          \
            VS_LOG_INFO("1 test has been failed");                                                                     \
        } else if (failed_test_result > 1) {                                                                           \
            VS_LOG_INFO("%lu tests have been failed", failed_test_result);                                             \
        }                                                                                                              \
    } while (0)

#define START_TEST(NAME)                                                                                               \
    do {                                                                                                               \
        BORDER;                                                                                                        \
        VS_LOG_INFO(" START TEST: %s ", NAME);                                                                         \
    } while (0)

#define START_ELEMENT(NAME)                                                                                            \
    do {                                                                                                               \
        VS_LOG_INFO(" TEST CASE : %s ", NAME);                                                                         \
    } while (0)

#define RESULT_OK                                                                                                      \
    do {                                                                                                               \
        VS_LOG_INFO("[TEST-SUCCESS]");                                                                                 \
    } while (0)

#define RESULT_ERROR                                                                                                   \
    do {                                                                                                               \
        VS_LOG_ERROR("[TEST-FAILURE]");                                                                                \
        failed_test_result++;                                                                                          \
        goto terminate;                                                                                                \
    } while (0)

#define TEST_CASE(NAME, TEST_ELEMENT)                                                                                  \
    do {                                                                                                               \
        START_ELEMENT(NAME);                                                                                           \
        if ((TEST_ELEMENT)) {                                                                                          \
            RESULT_OK;                                                                                                 \
        } else {                                                                                                       \
            RESULT_ERROR;                                                                                              \
        }                                                                                                              \
    } while (0)

#define TEST_CASE_OK(NAME, TEST_ELEMENT) TEST_CASE(NAME, true == (TEST_ELEMENT))

#define TEST_CASE_NOT_OK(NAME, TEST_ELEMENT) TEST_CASE(NAME, true != (TEST_ELEMENT))

#define VS_HEADER_SUBCASE(MESSAGE, ...) VS_LOG_INFO("    CASE: " MESSAGE, ##__VA_ARGS__)

bool
vs_test_erase_otp_provision();
bool
vs_test_create_device_key();
bool
vs_test_save_hl_keys();
#endif // VS_IOT_SDK_TESTS_HELPERS_H_
