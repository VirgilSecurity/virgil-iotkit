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

#ifndef VS_MACROS_H
#define VS_MACROS_H

#include <virgil/iot/logger/logger.h>

#define CHECK(CONDITION, MESSAGE, ...) do {                                                                   \
    if (!(CONDITION)) {                                                                                                \
        VS_LOG_ERROR((MESSAGE), ##__VA_ARGS__);                                                                        \
        goto terminate;                                                                                             \
    } \
    } while(0)

#define CHECK_RET(CONDITION, RETCODE, MESSAGE, ...) do {                                                                   \
    if (!(CONDITION)) {                                                                                                \
        VS_LOG_ERROR((MESSAGE), ##__VA_ARGS__);                                                                        \
        return (RETCODE);                                                                                              \
    } \
    } while(0)

#define BOOL_CHECK(CONDITION, MESSAGE, ...) CHECK((CONDITION), (MESSAGE), ##__VA_ARGS__)
#define BOOL_CHECK_RET(CONDITION, MESSAGE, ...) CHECK_RET((CONDITION), false, (MESSAGE), ##__VA_ARGS__)

#define MEMCMP_CHECK(BUF1, BUF2, SIZE)                                                                             \
    CHECK(memcmp((BUF1), (BUF2), (SIZE)) == 0,                                                                \
                   #BUF1 " is not equal to " #BUF2 " while comparing %d bytes",                                        \
                   (int)(SIZE))
#define MEMCMP_CHECK_RET(BUF1, BUF2, SIZE, RET)                                                                             \
    CHECK_RET(memcmp((BUF1), (BUF2), (SIZE)) == 0, (RET),                                                              \
                   #BUF1 " is not equal to " #BUF2 " while comparing %d bytes",                                        \
                   (int)(SIZE))

#define CHECK_NOT_ZERO(ARG)        CHECK((ARG), "Argument " #ARG " must not be zero")
#define CHECK_NOT_ZERO_RET(ARG, RETCODE)        CHECK_RET((ARG), (RETCODE), "Argument " #ARG " must not be zero")                                                                           \

#endif // VS_MACROS_H
