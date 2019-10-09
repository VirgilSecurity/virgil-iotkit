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

#include <virgil/iot/high-level/default/sdmp/prvs-server-impl.h>

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/prvs.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/status_code/status_code.h>

/******************************************************************************/
static bool
_prvs_server_def_dnid(void) {
    return false;
}

/******************************************************************************/
static vs_status_e
_prvs_server_def_device_info(vs_sdmp_prvs_devi_t *device_info, uint16_t buf_sz) {
    uint16_t key_sz = 0;
    vs_hsm_keypair_type_e ec_type;
    vs_pubkey_t *own_pubkey;
    uint16_t sign_sz = 0;
    vs_sign_t *sign;
    vs_status_e ret_code;

    // Check input parameters
    VS_IOT_ASSERT(device_info);

    // Fill MAC address
    vs_sdmp_mac_addr(NULL, &device_info->mac);

    // Fill Manufacture ID
    memcpy(device_info->manufacturer, vs_sdmp_device_manufacture(), VS_DEVICE_MANUFACTURE_ID_SIZE);

    // Fill device Type ID
    memcpy(device_info->device_type, vs_sdmp_device_type(), VS_DEVICE_DEVICE_TYPE_SIZE);

    // Fill Serial of device
    memcpy(device_info->serial, vs_sdmp_device_serial(), VS_DEVICE_SERIAL_SIZE);

    // Fill own public key
    own_pubkey = (vs_pubkey_t *)device_info->data;
    STATUS_CHECK_RET(vs_hsm_keypair_get_pubkey(PRIVATE_KEY_SLOT, own_pubkey->pubkey, PUBKEY_MAX_SZ, &key_sz, &ec_type),
                     "Unable to get public key");

    own_pubkey->key_type = VS_KEY_IOT_DEVICE;
    own_pubkey->ec_type = ec_type;
    device_info->data_sz = key_sz + sizeof(vs_pubkey_t);
    sign = (vs_sign_t *)((uint8_t *)own_pubkey + key_sz + sizeof(vs_pubkey_t));

    buf_sz -= device_info->data_sz;

    // Load signature
    STATUS_CHECK_RET(vs_hsm_slot_load(SIGNATURE_SLOT, (uint8_t *)sign, buf_sz, &sign_sz), "Unable to load slot");

    device_info->data_sz += sign_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_sdmp_prvs_impl_t
vs_prvs_server_default_impl(void) {
    vs_sdmp_prvs_impl_t res;

    // Setup functionality implementations
    memset(&res, 0, sizeof(res));
    res.is_initialized_func = _prvs_server_def_dnid;
    res.device_info_func = _prvs_server_def_device_info;

    return res;
}

/******************************************************************************/


