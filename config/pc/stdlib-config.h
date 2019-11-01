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

/*! \file stdlib-config.h
 * \brief Standart Library calls configuration
 */
#ifndef VS_IOT_SDK_STDLIB_CONFIG_H
#define VS_IOT_SDK_STDLIB_CONFIG_H

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "global-hal.h"

/** assert call */
#define VS_IOT_ASSERT    assert

/** calloc call */
#define VS_IOT_CALLOC    calloc

/** free call */
#define VS_IOT_FREE      free

/** malloc call */
#define VS_IOT_MALLOC    malloc

/** memcmp call */
#define VS_IOT_MEMCMP    memcmp

/** memcpy call */
#define VS_IOT_MEMCPY    memcpy

/** memset call */
#define VS_IOT_MEMSET    memset

/** memmove call */
#define VS_IOT_MEMMOVE   memmove

/** snprintf call */
#define VS_IOT_SNPRINTF  snprintf

/** sprintf call */
#define VS_IOT_SPRINTF   sprintf

/** strcpy call */
#define VS_IOT_STRCPY    strcpy

/** strncpy call */
#define VS_IOT_STRNCPY    strncpy

/** strncmp call */
#define VS_IOT_STRNCMP    strncmp

/** strstr call */
#define VS_IOT_STRSTR    strstr

/** strlen call */
#define VS_IOT_STRLEN    strlen

/** vsnprintf call */
#define VS_IOT_VSNPRINTF vsnprintf

/** conversion from time_t to ASCIIZ */
#define VS_IOT_ASCTIME(TIME_T)  asctime(localtime(&(TIME_T)))


#endif // VS_IOT_SDK_STDLIB_CONFIG_H
