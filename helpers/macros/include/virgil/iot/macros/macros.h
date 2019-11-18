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

/*! \file macros.h
 * \brief Macroses to simplify code.
 */

#ifndef VS_MACROS_H
#define VS_MACROS_H

#include <virgil/iot/logger/logger.h>

/** Check condition and goto if non-successful.
 *
 *  1. \a CONDITION is compared with zero code.
 *  2. If they are equal, \a MESSAGES is logged and function jumps to terminate label.
 *
 * \warning terminate label must be present in current function.
 *
 *  \param[in] CONDITION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 */
#define CHECK(CONDITION, MESSAGE, ...) do {                                                                   \
    if (!(CONDITION)) {                                                                                                \
        VS_LOG_ERROR((MESSAGE), ##__VA_ARGS__);                                                                        \
        goto terminate;                                                                                             \
    } \
    } while(0)

/** Check condition and return non-successful.
 *
 *  1. \a CONDITION is compared with zero code.
 *  2. If they are equal, \a MESSAGES is logged and function returns \a RETCODE.
 *
 *  \param[in] CONDITION Operation to be checked.
 *  \param[in] RETCODE Return code in case of error.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 *
 *  \return \a RETCODE in case of error
 */
#define CHECK_RET(CONDITION, RETCODE, MESSAGE, ...) do {                                                                   \
    if (!(CONDITION)) {                                                                                                \
        VS_LOG_ERROR((MESSAGE), ##__VA_ARGS__);                                                                        \
        return (RETCODE);                                                                                              \
    } \
    } while(0)

/** Check condition and goto if non-successful.
 *
 *  1. \a CONDITION is compared with boolean false.
 *  2. If they are equal, \a MESSAGES is logged and function jumps to terminate label.
 *
 * \warning terminate label must be present in current function.
 *
 *  \param[in] CONDITION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 */
#define BOOL_CHECK(CONDITION, MESSAGE, ...) CHECK((CONDITION), (MESSAGE), ##__VA_ARGS__)

/** Check condition and return non-successful.
 *
 *  1. \a CONDITION is compared with boolean false.
 *  2. If they are equal, \a MESSAGES is logged and function returns false.
 *
 *  \param[in] CONDITION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 *
 *  \return false in case of error
 */
#define BOOL_CHECK_RET(CONDITION, MESSAGE, ...) CHECK_RET((CONDITION), false, (MESSAGE), ##__VA_ARGS__)

/** Compares two buffer and goto if non-successful.
 *
 *  1. \a BUF1 is compared with \a BUF2. \a SIZE bytes are compared.
 *  2. If they are not equal, result message is logged and function jumps to terminate label.
 *
 * \warning terminate label must be present in current function.
 * \warning \a BUF1 and \a BUF2 sizes must be the same or bigger that \a SIZE.
 *
 *  \param[in] BUF1 First data buffer to be checked.
 *  \param[in] BUF2 Second data buffer to be checked.
 *  \param[in] SIZE Data size.
 */
#define MEMCMP_CHECK(BUF1, BUF2, SIZE)                                                                             \
    CHECK(memcmp((BUF1), (BUF2), (SIZE)) == 0,                                                                \
                   #BUF1 " is not equal to " #BUF2 " while comparing %d bytes",                                        \
                   (int)(SIZE))

/** Compares two buffer and returns if non-successful.
 *
 *  1. \a BUF1 is compared with \a BUF2. \a SIZE bytes are compared.
 *  2. If they are not equal, result mesage is logged and function returns \a RET.
 *
 * \warning terminate label must be present in current function.
 * \warning \a BUF1 and \a BUF2 sizes must be the same or bigger that \a SIZE.
 *
 *  \param[in] BUF1 First data buffer to be checked.
 *  \param[in] BUF2 Second data buffer to be checked.
 *  \param[in] SIZE Data size.
 *  \param[in] RET Return code in case of unsuccessful result.
 *
 *  \return \a RET in case of error
 */
#define MEMCMP_CHECK_RET(BUF1, BUF2, SIZE, RET)                                                                             \
    CHECK_RET(VS_IOT_MEMCMP((BUF1), (BUF2), (SIZE)) == 0, (RET),                                                              \
                   #BUF1 " is not equal to " #BUF2 " while comparing %d bytes",                                        \
                   (int)(SIZE))

/** Checks that \a ARG is non-zero and goto in case of zero one.
 *
 *  1. \a ARG is compared with zero.
 *  2. If \a ARG is zero, result message is logged and function jumps to terminate label.
 *
 * \warning terminate label must be present in current function.
 *
 *  \param[in] ARG Argument to be checked.
 */
#define CHECK_NOT_ZERO(ARG)        CHECK((ARG), "Argument " #ARG " must not be zero")

/** Checks that \a ARG is non-zero and returns in case of zero one.
 *
 *  1. \a ARG is compared with zero.
 *  2. If \a ARG is zero, result message is logged and returns \a RETCODE.
 *
 * \warning terminate label must be present in current function.
 *
 *  \param[in] ARG Argument to be checked.
 *  \param[in] RETCODE Return code in case of unsuccessful result.
 *
 *  \return \a RETCODE in case of error
 */
#define CHECK_NOT_ZERO_RET(ARG, RETCODE)        CHECK_RET((ARG), (RETCODE), "Argument " #ARG " must not be zero")                                                                           \

#define CHECK_BOOL(OPERATION, DESCRIPTION, ...)                                                                        \
    do {                                                                                                               \
        if (!(OPERATION)) {                                                                                            \
            VS_LOG_ERROR((DESCRIPTION), ##__VA_ARGS__);                                                                \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

// TODO : make real mem alloc or remove it !!!
#define CHECK_MEM_ALLOC(OPERATION, DESCRIPTION, ...) CHECK_BOOL(OPERATION, DESCRIPTION, ##__VA_ARGS__)

#endif // VS_MACROS_H
