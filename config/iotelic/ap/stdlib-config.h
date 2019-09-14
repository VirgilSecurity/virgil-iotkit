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

#ifndef VS_IOT_SDK_STDLIB_CONFIG_H
#define VS_IOT_SDK_STDLIB_CONFIG_H



#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <os_mem_api.h>

#define VS_IOT_ASSERT(...)
#define VS_IOT_CALLOC(NUM, SZ)  os_mem_malloc(0, (NUM) * (SZ))
#define VS_IOT_FREE             os_mem_free
#define VS_IOT_MALLOC(...)      os_mem_malloc(0, __VA_ARGS__)
#define VS_IOT_MEMCMP           os_mem_cmp
#define VS_IOT_MEMCPY           os_mem_cpy
#define VS_IOT_MEMMOVE          os_mem_move
#define VS_IOT_MEMSET           os_mem_set
#define VS_IOT_SNPRINTF         snprintf
#define VS_IOT_SPRINTF          sprintf
#define VS_IOT_STRCPY           strcpy
#define VS_IOT_STRLEN           strlen
#define VS_IOT_VSNPRINTF        vsnprintf



#endif // VS_IOT_SDK_STDLIB_CONFIG_H
