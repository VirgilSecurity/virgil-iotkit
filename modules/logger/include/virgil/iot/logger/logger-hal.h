//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

/*! \file logger-hal.h
 * \brief Logger HAL functions declarations
 *
 * These functions have to be implemented to use logger module. See #logger_usage for details.
 *
 * \section logger_hal_implementation Logger HAL Implementation
 *
 * \warning If #VS_IOT_LOGGER_USE_LIBRARY is set to 1, user has to provide logger output function
 * #vs_logger_output_hal. The goal of this function is to add a part of string to the output. It can be implemented as
 * shown :
 *
 * \code

#include <stdio.h>
bool
vs_logger_output_hal(const char *buffer) {
    if (!buffer) {
        return false;
    }

    return printf("%s", buffer) != 0;
}

 * \endcode
 *
 * \warning If #VS_IOT_LOGGER_OUTPUT_TIME is set to 1, user has to implement #vs_logger_current_time_hal function that
 * outputs current time. It can be implemented as shown below :
 *
 * \code

#include <stdio.h>
#include <time.h>

#if VS_IOT_LOGGER_OUTPUT_TIME == 1
bool
vs_logger_current_time_hal(void) {
    time_t result = time(NULL);
    if(result != -1) {
        printf( "%s", asctime(gmtime(&result)) );
        return true;
    }
    return false;
}
#endif // #if VS_IOT_LOGGER_OUTPUT_TIME == 1

 * \endcode
 */

#ifndef VS_IOT_SDK_LOGGER_HAL_H_
#define VS_IOT_SDK_LOGGER_HAL_H_

#include <stdbool.h>

/** Function signature for unterminated string output
 *
 * This is the HAL function that has to be implemented by user if #VS_IOT_LOGGER_USE_LIBRARY == 1. It sends string to
 * the output.
 *
 * \param[in] buffer Buffer with part of the string. Cannot be NULL
 *
 * \return true in case of success or false if any error occurs
 */
bool
vs_logger_output_hal(const char *buffer);

#if VS_IOT_LOGGER_OUTPUT_TIME == 1

/** Output current date/time function signature
 *
 * This is the HAL function that has to be implemented by user if #VS_IOT_LOGGER_OUTPUT_TIME == 1.
 * It adds current date and/or time to the output, e.g. by using vs_logger_output_hal.
 *
 * \return true in case of success or false if any error occurs
 */
bool
vs_logger_current_time_hal(void);

#endif // #if VS_IOT_LOGGER_OUTPUT_TIME == 1

#endif // VS_IOT_SDK_LOGGER_HAL_H_
