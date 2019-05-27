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

/*
 * VS_IOT_CONFIG_H
 * Config file path to substitute
 * This path is #define constant,
 * i. e. -DVS_IOT_CONFIG_H ${CMAKE_BINARY_PATH}/config.h
 */

/*
 * Assertions
 */

/*
 * VS_IOT_ASSERT(CONDITION)
 * Enable and setup this macros if you would like to compile assertions
 * CONDITION : condition that must be true
 * MESSAGE : output ASCIIZ-string with arguments to be output in case of false condition
 */

#include <assert.h>
#define VS_IOT_ASSERT(CONDITION, MESSAGE, ...) assert(CONDITION)

/********************
 **
 ** Logger
 **
 */

/*
 * VS_IOT_LOGGER_EOL
 * ASCIIZ string placed at the end of the output string
 * Normally this is "\n"
 */

#define VS_IOT_LOGGER_EOL "\n"

#endif // VIRGIL_IOT_SDK_CONFIG_H
