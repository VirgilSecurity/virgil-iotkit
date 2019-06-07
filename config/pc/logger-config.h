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

#ifndef VIRGIL_IOT_SDK_LOGGER_CONFIG_H
#define VIRGIL_IOT_SDK_LOGGER_CONFIG_H



/*
 * VS_IOT_LOGGER_ENABLE
 * Enables logger library.
 * Logger macroses will be empty if it is disabled.
 */

#define VS_IOT_LOGGER_ENABLE 1

#if VS_IOT_LOGGER_ENABLE == 1

/*
 * VS_IOT_LOGGER_MAX_BUFFER_SIZE
 * Defines maximum internal char buffer for output purposes.
 */

#define VS_IOT_LOGGER_MAX_BUFFER_SIZE 1024

/*
 * VS_IOT_LOGGER_USE_STATIC_BUFFER
 * Enables static buffer usage instead of stack one.
 * This can be done for single thread mode only.
 */

#define VS_IOT_LOGGER_USE_STATIC_BUFFER 1

/*
 * VS_IOT_LOGGER_USE_LIBRARY
 * Enables logger library usage instead of printf-like function call.
 */

#define VS_IOT_LOGGER_USE_LIBRARY 1

/*
 * VS_IOT_LOGGER_FUNCTION
 * Sends string directly to the printf-like function defined by this macros.
 * Used when VS_IOT_LOGGER_USE_LIBRARY == 0
 */

#include <stdio.h>
#define VS_IOT_LOGGER_FUNCTION printf

/*
 * VS_IOT_LOGGER_EOL
 * ASCIIZ string placed at the end of the output string.
 * Normally this is "\n".
 */

#define VS_IOT_LOGGER_EOL "\n"

/*
 * VS_IOT_LOGGER_OUTPUT_TIME
 * Enables current time output at the beginning of log string.
 * Requires vs_logger_current_time_hal function implementation.
 */

#define VS_IOT_LOGGER_OUTPUT_TIME   0

#else  // VS_IOT_LOGGER_ENABLE == 1

#define VS_IOT_LOGGER_USE_LIBRARY 0

#endif  // VS_IOT_LOGGER_ENABLE == 1



#endif // VIRGIL_IOT_SDK_LOGGER_CONFIG_H
