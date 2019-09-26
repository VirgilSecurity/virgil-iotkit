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

#include <virgil/iot/status_code/status_code.h>
#include <stdbool.h>
#include <stdlib-config.h>

/*************************************************************************/
const char *
vs_status_code_descr(vs_status_code_e status_code){

    switch(status_code){
        case VS_CODE_OK :
            return "Success";

        case VS_CODE_ERR_NULLPTR_ARGUMENT :
            return "Null pointer argument";
        case VS_CODE_ERR_ZERO_ARGUMENT :
            return "Zero argument";
        case VS_CODE_ERR_INCORRECT_ARGUMENT :
            return "Incorrect argument";
        case VS_CODE_ERR_INCORRECT_PARAMETER :
            return "Incorrect parameter";
        case VS_CODE_ERR_UNSUPPORTED_PARAMETER :
            return "Unsupported parameter";
        case VS_CODE_ERR_NO_CALLBACK :
            return "No callback function";
        case VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE :
            return "Unregistered mapping type";
        case VS_CODE_ERR_INCORRECT_SEND_REQUEST :
            return "Incorrect send request";
        case VS_CODE_ERR_NO_MEMORY :
            return "No memory";
        case VS_CODE_ERR_AMBIGUOUS_INIT_CALL :
            return "Ambiguous init call";
        case VS_CODE_ERR_VERIFY :
            return "Verify error";
        case VS_CODE_ERR_FILE:
            return "File processing error";
        case VS_CODE_ERR_FILE_READ:
            return "File read error";
        case VS_CODE_ERR_FILE_WRITE:
            return "File write error";
        case VS_CODE_ERR_FILE_DELETE:
            return "File delete error";
        case VS_CODE_ERR_UINT16_T:
            return "Value is bigger than uint16_t";
        case VS_CODE_ERR_UINT32_T :
            return "Value is bigger than uint32_t";

        case VS_CODE_AMOUNT_OF_CODES :
            VS_IOT_ASSERT(false && "Must not be returned");
            return "Amount of VS IoT status codes";
        default :
            VS_IOT_ASSERT(false && "Unsupported code");
            return "";
    }
}