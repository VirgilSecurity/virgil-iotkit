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
#include <stdlib.h>

#include <msgr/msgr-server-impl.h>
#include <virgil/iot/protocols/snap.h>

#include "helpers/app-helpers.h"

#define ENV_VAR_PREFIX "SENS_"
/******************************************************************************/
static vs_status_e
_snap_msgr_get_data_cb(uint8_t *data, uint32_t buf_sz, uint32_t *data_sz) {
    vs_status_e ret_code;
    vs_mac_addr_t mac_addr;
    uint8_t env_var_name[strlen(ENV_VAR_PREFIX) + sizeof(struct vs_mac_addr_t) * 2 + 1];
    uint32_t hex_len = sizeof(struct vs_mac_addr_t) * 2 + 1;
    char *env_var_value;

    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    memset(data, 0, buf_sz);
    *data_sz = 0;

    STATUS_CHECK_RET(vs_snap_mac_addr(NULL, &mac_addr), "Can't get mac addr");

    memcpy(env_var_name, ENV_VAR_PREFIX, strlen(ENV_VAR_PREFIX));
    CHECK_RET(
            vs_app_data_to_hex(mac_addr.bytes, sizeof(vs_mac_addr_t), env_var_name + strlen(ENV_VAR_PREFIX), &hex_len),
            VS_CODE_ERR_INCORRECT_ARGUMENT,
            "Error while convert to env var name");
    VS_LOG_DEBUG("Environment variable name : %s", env_var_name);

    env_var_value = getenv((char *)env_var_name);
    if (NULL != env_var_value) {
        uint32_t val_len = strlen(env_var_value);
        CHECK_RET(val_len < buf_sz, VS_CODE_ERR_TOO_SMALL_BUFFER, "Input buffer is too small");
        memcpy(data, env_var_value, val_len);
        *data_sz = strlen(env_var_value) + 1;
        VS_LOG_DEBUG("Environment variable value : %s", (char *)data);
    }

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
