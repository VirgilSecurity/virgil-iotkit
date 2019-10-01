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

#ifndef VS_IOT_SDK_STATUS_CODE
#define VS_IOT_SDK_STATUS_CODE

#include <virgil/iot/macros/macros.h>

typedef enum {
    VS_CODE_OK = 0,
    VS_CODE_ERR_NULLPTR_ARGUMENT,
    VS_CODE_ERR_ZERO_ARGUMENT,
    VS_CODE_ERR_INCORRECT_ARGUMENT,
    VS_CODE_ERR_INCORRECT_PARAMETER,
    VS_CODE_ERR_UNSUPPORTED_PARAMETER,
    VS_CODE_ERR_NO_CALLBACK,
    VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE,
    VS_CODE_ERR_INCORRECT_SEND_REQUEST,
    VS_CODE_ERR_NO_MEMORY,
    VS_CODE_ERR_TOO_SMALL_BUFFER,
    VS_CODE_ERR_AMBIGUOUS_INIT_CALL,
    VS_CODE_ERR_VERIFY,
    VS_CODE_ERR_FILE,
    VS_CODE_ERR_FILE_READ,
    VS_CODE_ERR_FILE_WRITE,
    VS_CODE_ERR_FILE_DELETE,
    VS_CODE_ERR_UINT16_T,
    VS_CODE_ERR_UINT32_T,
    VS_CODE_AMOUNT_OF_CODES    // Amount of VS IoT status codes
} vs_status_code_e;

const char *vs_status_code_descr(vs_status_code_e status_code);

#define STATUS_CHECK(OPERATION, MESSAGE, ...)   CHECK(VS_CODE_OK == (ret_code = (OPERATION)), (MESSAGE), ##__VA_ARGS__)
#define STATUS_CHECK_RET(OPERATION, MESSAGE, ...)   CHECK_RET(VS_CODE_OK == (ret_code = (OPERATION)), ret_code, (MESSAGE), ##__VA_ARGS__)

#endif // VS_IOT_SDK_STATUS_CODE
