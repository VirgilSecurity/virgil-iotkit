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

#ifndef VIRGIL_IOT_SDK_TESTS_HELPERS_H_
#define VIRGIL_IOT_SDK_TESTS_HELPERS_H_

#include <stdbool.h>
#include <virgil/iot/logger/logger.h>

extern size_t failed_test_result;

#define CHECK_RET(CONDITION, RETCODE, MESSAGE, ...)                                                                    \
    if (!(CONDITION)) {                                                                                                \
        VS_LOG_ERROR((MESSAGE), ##__VA_ARGS__);                                                                        \
        return (RETCODE);                                                                                              \
    }

#define CHECK_RET_BOOL(CONDITION, MESSAGE, ...) CHECK_RET(CONDITION, false, MESSAGE, ##__VA_ARGS__)

#define MEMCMP_CHECK_RET(BUF1, BUF2, SIZE)                                                                             \
    CHECK_RET_BOOL(memcmp((BUF1), (BUF2), (SIZE)) == 0,                                                                \
                   #BUF1 " is not equal to " #BUF2 " while comparing %d bytes",                                        \
                   (int)(SIZE))

#define RESULT_BUF_SIZE 1024

#define BORDER VS_LOG_INFO("------------------------------------------------------");

#define START_TESTS                                                                                                    \
    do {                                                                                                               \
        BORDER;                                                                                                        \
        VS_LOG_INFO("[TESTS-BEGIN]");                                                                                  \
    } while (0);

#define FINISH_TESTS                                                                                                   \
    do {                                                                                                               \
        BORDER;                                                                                                        \
        VS_LOG_INFO("[TESTS-END]");                                                                                    \
        if (failed_test_result == 0) {                                                                                 \
            VS_LOG_INFO("Test have been finished successfully");                                                       \
        } else if (failed_test_result == 1) {                                                                          \
            VS_LOG_INFO("1 test has been failed");                                                                     \
        } else if (failed_test_result >= 1) {                                                                          \
            VS_LOG_INFO("%lu tests have been failed", failed_test_result);                                             \
        }                                                                                                              \
    } while (0);

#define START_TEST(NAME)                                                                                               \
    do {                                                                                                               \
        BORDER;                                                                                                        \
        VS_LOG_INFO(" START TEST: %s ", NAME);                                                                         \
    } while (0);

#define START_ELEMENT(NAME)                                                                                            \
    do {                                                                                                               \
        VS_LOG_INFO(" TEST CASE : %s ", NAME);                                                                         \
    } while (0);

#define BOOL_CHECK_GOTO(OPERATION, DESCRIPTION, ...)                                                                   \
    if (!(OPERATION)) {                                                                                                \
        VS_LOG_ERROR(DESCRIPTION, ##__VA_ARGS__);                                                                      \
        goto terminate;                                                                                                \
    }

#define RESULT_OK                                                                                                      \
    do {                                                                                                               \
        VS_LOG_INFO("[TEST-SUCCESS]");                                                                                 \
    } while (0);

#define RESULT_ERROR                                                                                                   \
    do {                                                                                                               \
        VS_LOG_ERROR("[TEST-FAILURE]");                                                                                \
        failed_test_result++;                                                                                          \
        goto terminate;                                                                                                \
    } while (0);

#define TEST_CASE(NAME, TEST_ELEMENT)                                                                                  \
    do {                                                                                                               \
        START_ELEMENT(NAME);                                                                                           \
        if ((TEST_ELEMENT)) {                                                                                          \
            RESULT_OK;                                                                                                 \
        } else {                                                                                                       \
            RESULT_ERROR;                                                                                              \
        }                                                                                                              \
    } while (0);

#define TEST_CASE_OK(NAME, TEST_ELEMENT) TEST_CASE(NAME, true == (TEST_ELEMENT));

#define TEST_CASE_NOT_OK(NAME, TEST_ELEMENT) TEST_CASE(NAME, true != (TEST_ELEMENT));

#define TEST_CASES_NOT_OK(NAME, TEST_ELEMENTS) TEST_CASE(NAME, (TEST_ELEMENTS));

#define TEST_CASE_ERROR(NAME, TEST_ELEMENT) TEST_CASE(NAME, true != (TEST_ELEMENT));

#endif // VIRGIL_IOT_SDK_TESTS_HELPERS_H_
