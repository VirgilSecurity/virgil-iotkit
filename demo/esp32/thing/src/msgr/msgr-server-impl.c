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

#include <stdio.h>
#include <string.h>
#include <msgr/msgr-server-impl.h>
#include <private/utoa_fast_div.h>

static uint8_t demo_counter = 0;
/******************************************************************************/
static vs_status_e
_snap_msgr_get_data_cb(uint8_t *data, uint32_t buf_sz, uint32_t *data_sz) {
    char buf[11];
    char *result;

    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(buf_sz > 4, VS_CODE_ERR_INCORRECT_ARGUMENT, "Input buffer too small");

    result = utoa_fast_div((uint32_t)demo_counter, (char *)buf);
    memcpy(data, result, result - buf);
    *data_sz = result - buf;
    ++demo_counter;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_snap_msgr_set_data_cb(uint8_t *data, uint32_t data_sz) {
    return VS_CODE_OK;
}


/******************************************************************************/
vs_snap_msgr_server_service_t
vs_snap_msgr_server_impl(void) {
    vs_snap_msgr_server_service_t msgr_server_cb = {_snap_msgr_get_data_cb, _snap_msgr_set_data_cb};
    return msgr_server_cb;
}
