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

#ifndef VIRGIL_IOT_SDK_CONFIG_H
#define VIRGIL_IOT_SDK_CONFIG_H

/********************
 **
 **   General config
 **
 ********************
 */

/*
 * VIRGIL_IOT_CONFIG_H_DIRECTORY
 * Directory containing virgil-iot-sdk-config.h file.
 * Used as target_include_directories( ... PRIVATE $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_H_DIRECTORY}> ).
 * If it is not specified, default one will be used.
 */

/********************
 **
 **   Standard Library calls
 **
 ********************
 */

/*
 * VS_IOT_ASSERT
 * Enable and setup this macros if you would like to compile assertions
 * CONDITION : condition that must be true
 * MESSAGE : output ASCIIZ-string with arguments to be output in case of false condition
 * ... : arguments containing the data to output for "assert failed" message.
 */

#include <assert.h>
#define VS_IOT_ASSERT(CONDITION, MESSAGE, ...) assert(CONDITION)

/*
 * VS_IOT_SNPRINTF
 * Loads the data from the given locations, converts them to character string equivalents and writes the results to
 * a variety of sinks.
 * Normally this is snprintf function from standard C library
 * BUFFER : pointer to a character string to write to.
 * BUFFER_SIZE : up to BUFFER_SIZE - 1 characters may be written, plus the null terminator.
 * FORMAT : pointer to a null-terminated character string specifying how to interpret the data.
 * ... : arguments containing the data to print.
 */

#include <stdio.h>
#define VS_IOT_SNPRINTF(BUFFER, BUFFER_SIZE, FORMAT, ...) snprintf((BUFFER), (BUFFER_SIZE), (FORMAT), ## __VA_ARGS__ )

/*
 * VS_IOT_SPRINTF
 * Loads the data from the given locations, converts them to character string equivalents and writes the results to
 * a variety of sinks.
 * Normally this is snprintf function from standard C library
 * BUFFER : pointer to a character string to write to.
 * FORMAT : pointer to a null-terminated character string specifying how to interpret the data.
 * ... : arguments containing the data to print.
 */

#include <stdio.h>
#define VS_IOT_SPRINTF(BUFFER, FORMAT, ...) sprintf((BUFFER), (FORMAT), ## __VA_ARGS__ )

/*
 * VS_IOT_STRCPY
 * Copies the null-terminated byte string pointed to by SOURCE, including the null terminator, to the character array
 * whose first element is pointed to by DESTINATION.
 * Normally this is strcpy function from standard C library
 * DESTINATION : pointer to the character array to write to.
 * SOURCE : pointer to the null-terminated byte string to copy from.
 */

#include <string.h>
#define VS_IOT_STRCPY(DESTINATION, SOURCE) strcpy((DESTINATION), (SOURCE))

/*
 * VS_IOT_VSNPRINTF
 * Loads the data from the locations, defined by vlist, converts them to character string equivalents and writes
 * the results to a variety of sinks.
 * Normally this is vsnprintf function from standard C library
 * BUFFER : pointer to a character string to write to.
 * BUFFER_SIZE : up to BUFFER_SIZE - 1 characters may be written, plus the null terminator.
 * FORMAT : pointer to a null-terminated character string specifying how to interpret the data.
 * VLIST : variable argument list containing the data to print.
 */

#include <stdio.h>
#define VS_IOT_VSNPRINTF(BUFFER, BUFFER_SIZE, FORMAT, VLIST) vsnprintf((BUFFER), (BUFFER_SIZE), (FORMAT), (VLIST))

/********************
 **
 **   Logger
 **
 ********************
 */

/*
 * VS_IOT_LOGGER_OUTPUT
 * Sends string to the output.
 * Function call as described below assumed :
 *   bool vs_logger_implement(const char *buf);
 * Receives pointer to the ASCIIZ string.
 * Returns true in case of success or false in any error occur.
 */

#include <stdbool.h>
bool vs_logger_implement(const char *buf);

#define VS_IOT_LOGGER_OUTPUT(STRING)    vs_logger_implement(STRING)

/*
 * VS_IOT_LOGGER_HEX_FORMAT
 * Output format for each byte.
 * Used to output data in hex format by VS_IOT_SPRINTF call.
 */

#define VS_IOT_LOGGER_HEX_FORMAT    "%02X"

/*
 * VS_IOT_LOGGER_HEX_BUFFER_SIZE
 * VS_IOT_LOGGER_HEX_FORMAT data buffer size without null terminator
 */

#define VS_IOT_LOGGER_HEX_BUFFER_SIZE 2

/*
 * VS_IOT_LOGGER_EOL
 * ASCIIZ string placed at the end of the output string
 * Normally this is "\n"
 */

#define VS_IOT_LOGGER_EOL "\n"

/*
 * VS_IOT_LOGGER_OUTPUT_TIME
 * Function call to generate current time directly to the output buffer, i. e. by using
 * vs_logger_implement call.
 * Must return true in case of success or false if any error occurs.
 */

#define VS_IOT_LOGGER_OUTPUT_TIME   true

#endif // VIRGIL_IOT_SDK_CONFIG_H
