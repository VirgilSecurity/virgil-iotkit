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

#include <virgil/iot/protocols/sdmp/generated/sdmp_cvt.h>
#include <virgil/iot/protocols/sdmp/prvs/prvs-server.h>
#include <virgil/iot/protocols/sdmp/sdmp_private.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <stdbool.h>
#include <string.h>

#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/trust_list/trust_list.h>

static vs_sdmp_service_t _prvs_server = {0, 0, 0, 0, 0};
static bool _prvs_service_ready = false;

/******************************************************************************/
static bool
vs_prvs_server_is_initialized(void) {
    // TODO: Check is device initialized
    return false;
}

/******************************************************************************/
static vs_status_e
vs_prvs_server_device_info(vs_sdmp_prvs_devi_t *device_info, uint16_t buf_sz) {
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
    memcpy(device_info->device_type, vs_sdmp_device_type(), VS_DEVICE_TYPE_SIZE);

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
static vs_status_e
vs_prvs_save_data(vs_sdmp_prvs_element_e element_id, const uint8_t *data, uint16_t data_sz) {
    uint16_t slot;
    vs_status_e ret_code;

    STATUS_CHECK_RET(vs_provision_get_slot_num((vs_provision_element_id_e)element_id, &slot), "Unable to get slot");

    return vs_hsm_slot_save(slot, data, data_sz);
}

/******************************************************************************/
static vs_status_e
vs_prvs_finalize_storage(vs_pubkey_t *asav_response, uint16_t *resp_sz) {
    uint16_t key_sz = 0;
    vs_hsm_keypair_type_e ec_type;
    vs_status_e ret_code;

    VS_IOT_ASSERT(asav_response);
    VS_IOT_ASSERT(resp_sz);

    STATUS_CHECK_RET(vs_hsm_slot_delete(PRIVATE_KEY_SLOT), "Unable to delete PRIVATE slot");
    STATUS_CHECK_RET(vs_hsm_slot_delete(REC1_KEY_SLOT), "Unable to delete REC1_KEY slot");
    STATUS_CHECK_RET(vs_hsm_slot_delete(REC2_KEY_SLOT), "Unable to delete REC2_KEY slot");
    STATUS_CHECK_RET(vs_hsm_keypair_create(PRIVATE_KEY_SLOT, VS_KEYPAIR_EC_SECP256R1), "Unable to create keypair");
    STATUS_CHECK_RET(
            vs_hsm_keypair_get_pubkey(PRIVATE_KEY_SLOT, asav_response->pubkey, PUBKEY_MAX_SZ, &key_sz, &ec_type),
            "Unable to get public key");

    asav_response->key_type = VS_KEY_IOT_DEVICE;
    asav_response->ec_type = ec_type;
    *resp_sz = sizeof(vs_pubkey_t) + key_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
vs_prvs_start_save_tl(const uint8_t *data, uint16_t data_sz) {
    vs_tl_element_info_t info;

    info.id = VS_TL_ELEMENT_TLH;
    info.index = 0;

    return vs_tl_save_part(&info, data, data_sz);
}

/******************************************************************************/
static vs_status_e
vs_prvs_save_tl_part(const uint8_t *data, uint16_t data_sz) {
    vs_tl_element_info_t info;

    info.id = VS_TL_ELEMENT_TLC;
    info.index = 0;

    return vs_tl_save_part(&info, data, data_sz);
}

/******************************************************************************/
static vs_status_e
vs_prvs_finalize_tl(const uint8_t *data, uint16_t data_sz) {
    vs_tl_element_info_t info;

    info.id = VS_TL_ELEMENT_TLF;
    info.index = 0;

    return vs_tl_save_part(&info, data, data_sz);
}

/******************************************************************************/
static vs_status_e
vs_prvs_sign_data(const uint8_t *data, uint16_t data_sz, uint8_t *signature, uint16_t buf_sz, uint16_t *signature_sz) {
    uint16_t sign_sz;
    uint16_t pubkey_sz;
    vs_status_e ret_code;

    VS_IOT_ASSERT(signature_sz);
    VS_IOT_ASSERT(data);
    VS_IOT_ASSERT(signature);

    vs_sdmp_prvs_sgnp_req_t *request = (vs_sdmp_prvs_sgnp_req_t *)data;
    vs_sign_t *response = (vs_sign_t *)signature;
    int hash_len = vs_hsm_get_hash_len(request->hash_type);
    vs_hsm_keypair_type_e keypair_type;

    if (hash_len <= 0 || buf_sz <= sizeof(vs_sign_t)) {
        return VS_CODE_ERR_INCORRECT_PARAMETER;
    }
    uint8_t hash[hash_len];
    buf_sz -= sizeof(vs_sign_t);

    STATUS_CHECK_RET(vs_hsm_hash_create(request->hash_type,
                                        (uint8_t *)&request->data,
                                        data_sz - sizeof(vs_sdmp_prvs_sgnp_req_t),
                                        hash,
                                        hash_len,
                                        &sign_sz),
                     "Unable to create hash");

    STATUS_CHECK_RET(
            vs_hsm_ecdsa_sign(PRIVATE_KEY_SLOT, request->hash_type, hash, response->raw_sign_pubkey, buf_sz, &sign_sz),
            "Unable to sign");

    buf_sz -= sign_sz;

    STATUS_CHECK_RET(vs_hsm_keypair_get_pubkey(
                             PRIVATE_KEY_SLOT, response->raw_sign_pubkey + sign_sz, buf_sz, &pubkey_sz, &keypair_type),
                     "Unable to get public key");

    response->signer_type = VS_KEY_IOT_DEVICE;
    response->hash_type = (uint8_t)request->hash_type;
    response->ec_type = (uint8_t)keypair_type;
    *signature_sz = sizeof(vs_sign_t) + sign_sz + pubkey_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_dnid_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const uint16_t request_sz,
                           uint8_t *response,
                           const uint16_t response_buf_sz,
                           uint16_t *response_sz) {

    vs_sdmp_prvs_dnid_element_t *dnid_response = (vs_sdmp_prvs_dnid_element_t *)response;

    // Check input parameters
    VS_IOT_ASSERT(response_buf_sz >= sizeof(vs_sdmp_prvs_dnid_element_t));

    if (vs_prvs_server_is_initialized()) {
        // No need in response, because device is initialized already
        return VS_CODE_COMMAND_NO_RESPONSE;
    }

    // Fill MAC address
    vs_sdmp_mac_addr(netif, &dnid_response->mac_addr);
    dnid_response->device_roles = vs_sdmp_device_roles();
    *response_sz = sizeof(vs_sdmp_prvs_dnid_element_t);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_key_save_process_request(const struct vs_netif_t *netif,
                               vs_sdmp_element_t element_id,
                               const uint8_t *key,
                               const uint16_t key_sz) {
    return vs_prvs_save_data(element_id, key, key_sz);
}

/******************************************************************************/
static vs_status_e
_prvs_devi_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const uint16_t request_sz,
                           uint8_t *response,
                           const uint16_t response_buf_sz,
                           uint16_t *response_sz) {

    vs_status_e ret_code;
    vs_sdmp_prvs_devi_t *devi_response = (vs_sdmp_prvs_devi_t *)response;

    STATUS_CHECK_RET(vs_prvs_server_device_info(devi_response, response_buf_sz), "Unable to get device info");

    *response_sz = sizeof(vs_sdmp_prvs_devi_t) + devi_response->data_sz;

    // Normalize byte order
    vs_sdmp_prvs_devi_t_encode(devi_response);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_asav_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const uint16_t request_sz,
                           uint8_t *response,
                           const uint16_t response_buf_sz,
                           uint16_t *response_sz) {

    vs_pubkey_t *asav_response = (vs_pubkey_t *)response;
    return vs_prvs_finalize_storage(asav_response, response_sz);
}

/******************************************************************************/
static vs_status_e
_prvs_asgn_process_request(const struct vs_netif_t *netif,
                           const uint8_t *request,
                           const uint16_t request_sz,
                           uint8_t *response,
                           const uint16_t response_buf_sz,
                           uint16_t *response_sz) {

    vs_status_e ret_code;
    uint16_t result_sz;

    STATUS_CHECK_RET(vs_prvs_sign_data(request, request_sz, response, response_buf_sz, &result_sz),
                     "Unable to sign data");

    *response_sz = result_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_start_tl_process_request(const struct vs_netif_t *netif, const uint8_t *request, const uint16_t request_sz) {
    vs_status_e ret_code;
    STATUS_CHECK_RET(vs_prvs_start_save_tl(request, request_sz), "Unable to start save Trust List");
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_tl_part_process_request(const struct vs_netif_t *netif, const uint8_t *request, const uint16_t request_sz) {
    vs_status_e ret_code;
    STATUS_CHECK_RET(vs_prvs_save_tl_part(request, request_sz), "Unable to save Trust List part");
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_finalize_tl_process_request(const struct vs_netif_t *netif, const uint8_t *request, const uint16_t request_sz) {
    vs_status_e ret_code;
    STATUS_CHECK_RET(vs_prvs_finalize_tl(request, request_sz), "Unable to finalize Trust List");
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_service_request_processor(const struct vs_netif_t *netif,
                                vs_sdmp_element_t element_id,
                                const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {
    *response_sz = 0;

    switch (element_id) {
    case VS_PRVS_DNID:
        return _prvs_dnid_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    case VS_PRVS_DEVI:
        return _prvs_devi_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    case VS_PRVS_ASAV:
        return _prvs_asav_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    case VS_PRVS_ASGN:
        return _prvs_asgn_process_request(netif, request, request_sz, response, response_buf_sz, response_sz);

    case VS_PRVS_TLH:
        return _prvs_start_tl_process_request(netif, request, request_sz);

    case VS_PRVS_TLC:
        return _prvs_tl_part_process_request(netif, request, request_sz);

    case VS_PRVS_TLF:
        return _prvs_finalize_tl_process_request(netif, request, request_sz);

    case VS_PRVS_PBR1:
    case VS_PRVS_PBR2:
    case VS_PRVS_PBA1:
    case VS_PRVS_PBA2:
    case VS_PRVS_PBT1:
    case VS_PRVS_PBT2:
    case VS_PRVS_PBF1:
    case VS_PRVS_PBF2:
    case VS_PRVS_SGNP:
        return _prvs_key_save_process_request(netif, element_id, request, request_sz);

    default:
        VS_LOG_ERROR("Unsupported PRVS request %d", element_id);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
static void
_prepare_prvs_service() {
    _prvs_server.user_data = 0;
    _prvs_server.id = VS_PRVS_SERVICE_ID;
    _prvs_server.request_process = _prvs_service_request_processor;
    _prvs_server.response_process = NULL;
    _prvs_server.periodical_process = NULL;
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_prvs_server(void) {
    if (!_prvs_service_ready) {
        _prepare_prvs_service();
        _prvs_service_ready = true;
    }
    return &_prvs_server;
}

/******************************************************************************/
