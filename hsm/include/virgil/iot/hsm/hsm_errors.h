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

#ifndef VS_HSM_ERRORS_API_H
#define VS_HSM_ERRORS_API_H

typedef enum {
    VS_HSM_ERR_OK,
    VS_HSM_ERR_INVAL,      // invalid parameters
    VS_HSM_ERR_NOMEM,      // out of memory
    VS_HSM_ERR_NOSUPP,     // not supported
    VS_HSM_ERR_NOSEC_WL,   // not secure due to white list
    VS_HSM_ERR_NOT_EXIST,  // not exist
    VS_HSM_ERR_AGAIN,      // again
    VS_HSM_ERR_NOT_READY,  // device not ready
    VS_HSM_ERR_EXIST,      // already exist
    VS_HSM_ERR_BUSY,       // busy
    VS_HSM_ERR_PENDING,    // pending
    VS_HSM_ERR_FAIL,       // failed
    VS_HSM_ERR_NOSEC_BL,   // not secure due to black list
    VS_HSM_ERR_CRC_LEN,    // calc crc but len < 0
    VS_HSM_ERR_NULL_PTR,   // NULL pointer
    VS_HSM_ERR_CRYPTO,     // error during crypto operation
    VS_HSM_ERR_NOT_AUTH    // not authenticated
} vs_hsm_err_code_e;

#endif // VS_HSM_ERRORS_API_H
