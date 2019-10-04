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
    VS_CODE_ERR_NULLPTR_ARGUMENT = -1,
    VS_CODE_ERR_ZERO_ARGUMENT = -2,
    VS_CODE_ERR_INCORRECT_ARGUMENT = -3,
    VS_CODE_ERR_INCORRECT_PARAMETER = -4,
    VS_CODE_ERR_UNSUPPORTED_PARAMETER = -5,
    VS_CODE_ERR_AMBIGUOUS_INIT_CALL = -6,
    VS_CODE_ERR_CTX_NOT_READY = -7,
    VS_CODE_ERR_NOT_IMPLEMENTED = -8,
    VS_CODE_ERR_NOT_FOUND = -9,

    VS_CODE_ERR_NO_CALLBACK = -10,
    VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE = -11,
    VS_CODE_ERR_INCORRECT_SEND_REQUEST = -12,

    VS_CODE_ERR_NO_MEMORY = -20,
    VS_CODE_ERR_TOO_SMALL_BUFFER = -21,
    VS_CODE_ERR_FORMAT_OVERFLOW = -22,

    VS_CODE_ERR_VERIFY = -30,
    VS_CODE_ERR_UNSUPPORTED = -31,
    VS_CODE_ERR_CRYPTO = -32,

    VS_CODE_ERR_FILE = -40,
    VS_CODE_ERR_FILE_READ = -41,
    VS_CODE_ERR_FILE_WRITE = -42,
    VS_CODE_ERR_FILE_DELETE = -43,

    VS_CODE_ERR_CLOUD = -50,
    VS_CODE_ERR_JSON = -51,
    VS_CODE_ERR_REQUEST_PREPARE = -52,
    VS_CODE_ERR_REQUEST_SEND = -53,

    VS_CODE_ERR_PRVS_UNKNOWN = -60,

    VS_CODE_ERR_SDMP_UNKNOWN = -70,
    VS_CODE_ERR_SDMP_NOT_MY_PACKET = -71,
    VS_CODE_ERR_SDMP_TOO_MUCH_SERVICES = -72,

    VS_CODE_ERR_THREAD = -80,
    VS_CODE_ERR_NO_SIMULATOR = -81,
    VS_CODE_ERR_SOCKET = -82,
    VS_CODE_ERR_PLC = -83,

} vs_status_code_e;

#define STATUS_CHECK(OPERATION, MESSAGE, ...)   CHECK(VS_CODE_OK == (OPERATION), (MESSAGE), ##__VA_ARGS__)
#define STATUS_CHECK_RET(OPERATION, MESSAGE, ...)   CHECK_RET(VS_CODE_OK == (ret_code = (OPERATION)), ret_code, (MESSAGE), ##__VA_ARGS__)
#define STATUS_CHECK_RET_BOOL(OPERATION, MESSAGE, ...)   BOOL_CHECK_RET(VS_CODE_OK == (OPERATION), (MESSAGE), ##__VA_ARGS__)

#endif // VS_IOT_SDK_STATUS_CODE
