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
#include <virgil/iot/protocols/sdmp/sdmp_private.h>
#include <virgil/iot/protocols/sdmp/prvs/prvs-client.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib-config.h>
#include <string.h>

#if !VS_SDMP_FACTORY
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/trust_list/trust_list.h>
#endif // !VS_SDMP_FACTORY

static vs_sdmp_service_t _prvs_service = {0};
static bool _prvs_service_ready = false;
static vs_sdmp_prvs_dnid_list_t *_prvs_dnid_list = 0;

// External functions for access to upper level implementations
static vs_sdmp_prvs_impl_t _prvs_impl = {0};

// Last result
#define PRVS_BUF_SZ (1024)
static vs_status_e _last_res = VS_CODE_ERR_PRVS_UNKNOWN;
static uint16_t _last_data_sz = 0;
static uint8_t _last_data[PRVS_BUF_SZ];

#if !VS_SDMP_FACTORY
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

#endif // !VS_SDMP_FACTORY

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
    VS_IOT_ASSERT(_prvs_impl.is_initialized_func);
    VS_IOT_ASSERT(response_buf_sz >= sizeof(vs_sdmp_prvs_dnid_element_t));

    if (_prvs_impl.is_initialized_func()) {
        // No need in response, because device is initialized already
        return VS_CODE_COMMAND_NO_RESPONSE;
    }


    // Fill MAC address
    vs_sdmp_mac_addr(netif, &dnid_response->mac_addr);
    dnid_response->device_roles = 0;
    *response_sz = sizeof(vs_sdmp_prvs_dnid_element_t);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_dnid_process_response(const struct vs_netif_t *netif, const uint8_t *response, const uint16_t response_sz) {

    vs_sdmp_prvs_dnid_element_t *dnid_response = (vs_sdmp_prvs_dnid_element_t *)response;

    if (_prvs_dnid_list && _prvs_dnid_list->count < DNID_LIST_SZ_MAX) {
        memcpy(&_prvs_dnid_list->elements[_prvs_dnid_list->count], dnid_response, sizeof(vs_sdmp_prvs_dnid_element_t));
        _prvs_dnid_list->count++;

        return VS_CODE_OK;
    }

    return VS_CODE_ERR_PRVS_UNKNOWN;
}

/******************************************************************************/
static vs_status_e
_prvs_key_save_process_request(const struct vs_netif_t *netif,
                               vs_sdmp_element_t element_id,
                               const uint8_t *key,
                               const uint16_t key_sz) {
    VS_IOT_ASSERT(_prvs_impl.save_data_func);
    return _prvs_impl.save_data_func(element_id, key, key_sz);
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


    VS_IOT_ASSERT(_prvs_impl.device_info_func);
    STATUS_CHECK_RET(_prvs_impl.device_info_func(devi_response, response_buf_sz), "Unable to get device info");

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

    VS_IOT_ASSERT(_prvs_impl.finalize_storage_func);

    return _prvs_impl.finalize_storage_func(asav_response, response_sz);
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

    VS_IOT_ASSERT(_prvs_impl.sign_data_func);

    STATUS_CHECK_RET(_prvs_impl.sign_data_func(request, request_sz, response, response_buf_sz, &result_sz),
                     "Unable to sign data");

    *response_sz = result_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_start_tl_process_request(const struct vs_netif_t *netif, const uint8_t *request, const uint16_t request_sz) {
    vs_status_e ret_code;

    VS_IOT_ASSERT(_prvs_impl.start_save_tl_func);
    STATUS_CHECK_RET(_prvs_impl.start_save_tl_func(request, request_sz), "Unable to start save Trust List");

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_tl_part_process_request(const struct vs_netif_t *netif, const uint8_t *request, const uint16_t request_sz) {
    vs_status_e ret_code;

    VS_IOT_ASSERT(_prvs_impl.save_tl_part_func);
    STATUS_CHECK_RET(_prvs_impl.save_tl_part_func(request, request_sz), "Unable to save Trust List part");

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_prvs_finalize_tl_process_request(const struct vs_netif_t *netif, const uint8_t *request, const uint16_t request_sz) {
    vs_status_e ret_code;

    VS_IOT_ASSERT(_prvs_impl.finalize_tl_func);
    STATUS_CHECK_RET(_prvs_impl.finalize_tl_func(request, request_sz), "Unable to finalize Trust List");

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

    // Process DNID

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
        return VS_CODE_ERR_UNSUPPORTED_PARAMETER;
    }
}

/******************************************************************************/
static vs_status_e
_prvs_service_response_processor(const struct vs_netif_t *netif,
                                 vs_sdmp_element_t element_id,
                                 bool is_ack,
                                 const uint8_t *response,
                                 const uint16_t response_sz) {

    VS_IOT_ASSERT(_prvs_impl.stop_wait_func);

    switch (element_id) {
    case VS_PRVS_DNID:
        return _prvs_dnid_process_response(netif, response, response_sz);

    default: {
        if (response_sz && response_sz < PRVS_BUF_SZ) {
            _last_data_sz = response_sz;
            memcpy(_last_data, response, response_sz);
        }

        _prvs_impl.stop_wait_func(&_last_res, is_ack ? VS_CODE_OK : VS_CODE_ERR_PRVS_UNKNOWN);

        return VS_CODE_OK;
    }
    }
}

/******************************************************************************/
static vs_status_e
_configure_hal(vs_sdmp_prvs_impl_t impl) {
    VS_IOT_MEMSET(&_prvs_impl, 0, sizeof(_prvs_impl));

#if !VS_SDMP_FACTORY
    _prvs_impl.save_data_func = &vs_prvs_save_data;
    _prvs_impl.finalize_storage_func = &vs_prvs_finalize_storage;
    _prvs_impl.start_save_tl_func = &vs_prvs_start_save_tl;
    _prvs_impl.save_tl_part_func = &vs_prvs_save_tl_part;
    _prvs_impl.finalize_tl_func = &vs_prvs_finalize_tl;
    _prvs_impl.sign_data_func = &vs_prvs_sign_data;
#endif // !VS_SDMP_FACTORY

    if (impl.save_data_func) {
        _prvs_impl.save_data_func = impl.save_data_func;
    }

    if (impl.load_data_func) {
        _prvs_impl.load_data_func = impl.load_data_func;
    }

    if (impl.finalize_storage_func) {
        _prvs_impl.finalize_storage_func = impl.finalize_storage_func;
    }

    if (impl.start_save_tl_func) {
        _prvs_impl.start_save_tl_func = impl.start_save_tl_func;
    }

    if (impl.save_tl_part_func) {
        _prvs_impl.save_tl_part_func = impl.save_tl_part_func;
    }

    if (impl.finalize_tl_func) {
        _prvs_impl.finalize_tl_func = impl.finalize_tl_func;
    }

    if (impl.sign_data_func) {
        _prvs_impl.sign_data_func = impl.sign_data_func;
    }

    _prvs_impl.is_initialized_func = impl.is_initialized_func;
    _prvs_impl.device_info_func = impl.device_info_func;
    _prvs_impl.wait_func = impl.wait_func;
    _prvs_impl.stop_wait_func = impl.stop_wait_func;

    return VS_CODE_OK;
}
/******************************************************************************/
static void
_prepare_prvs_service() {
    _prvs_service.user_data = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
    _prvs_service.id = VS_PRVS_SERVICE_ID;
#pragma GCC diagnostic pop
    _prvs_service.request_process = _prvs_service_request_processor;
    _prvs_service.response_process = _prvs_service_response_processor;
    _prvs_service.periodical_process = NULL;
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_prvs_service(vs_sdmp_prvs_impl_t impl) {
    if (!_prvs_service_ready) {
        _prepare_prvs_service();
        _configure_hal(impl);
        _prvs_service_ready = true;
    }

    return &_prvs_service;
}

/******************************************************************************/
vs_status_e
vs_sdmp_prvs_uninitialized_devices(const vs_netif_t *netif, vs_sdmp_prvs_dnid_list_t *list, uint32_t wait_ms) {
    vs_status_e ret_code;

    VS_IOT_ASSERT(_prvs_impl.wait_func);

    // Set storage for DNID request
    _prvs_dnid_list = list;
    memset(_prvs_dnid_list, 0, sizeof(*_prvs_dnid_list));

    // Send request
    STATUS_CHECK_RET(vs_sdmp_send_request(netif, NULL, VS_PRVS_SERVICE_ID, VS_PRVS_DNID, 0, 0), "Send request error");

    // Wait request
    vs_impl_msleep(wait_ms);

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_sdmp_prvs_device_info(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_sdmp_prvs_devi_t *device_info,
                         uint16_t buf_sz,
                         uint32_t wait_ms) {
    uint16_t sz;

    if (VS_CODE_OK == vs_sdmp_prvs_get(netif, mac, VS_PRVS_DEVI, (uint8_t *)device_info, buf_sz, &sz, wait_ms)) {
        vs_sdmp_prvs_devi_t_decode(device_info);
        return VS_CODE_OK;
    }
    return VS_CODE_ERR_PRVS_UNKNOWN;
}

/******************************************************************************/
static void
_reset_last_result() {
    _last_res = VS_CODE_ERR_PRVS_UNKNOWN;
    _last_data_sz = 0;
}

/******************************************************************************/
vs_status_e
vs_sdmp_prvs_set(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_sdmp_prvs_element_e element,
                 const uint8_t *data,
                 uint16_t data_sz,
                 uint32_t wait_ms) {

    vs_status_e ret_code;
    VS_IOT_ASSERT(_prvs_impl.wait_func);

    _reset_last_result();

    // Send request
    STATUS_CHECK_RET(vs_sdmp_send_request(netif, mac, VS_PRVS_SERVICE_ID, element, data, data_sz),
                     "Send request error");

    // Wait request
    _prvs_impl.wait_func(wait_ms, &_last_res, VS_CODE_ERR_PRVS_UNKNOWN);

    return _last_res;
}

/******************************************************************************/
vs_status_e
vs_sdmp_prvs_get(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_sdmp_prvs_element_e element,
                 uint8_t *data,
                 uint16_t buf_sz,
                 uint16_t *data_sz,
                 uint32_t wait_ms) {

    vs_status_e ret_code;
    VS_IOT_ASSERT(_prvs_impl.wait_func);

    _reset_last_result();

    // Send request
    STATUS_CHECK_RET(vs_sdmp_send_request(netif, mac, VS_PRVS_SERVICE_ID, element, 0, 0), "Send request error");

    // Wait request
    _prvs_impl.wait_func(wait_ms, &_last_res, VS_CODE_ERR_PRVS_UNKNOWN);

    // Pass data
    if (VS_CODE_OK == _last_res && _last_data_sz <= buf_sz) {
        memcpy(data, _last_data, _last_data_sz);
        *data_sz = _last_data_sz;
        return VS_CODE_OK;
    }

    return VS_CODE_ERR_PRVS_UNKNOWN;
}

/******************************************************************************/
vs_status_e
vs_sdmp_prvs_save_provision(const vs_netif_t *netif,
                            const vs_mac_addr_t *mac,
                            uint8_t *asav_res,
                            uint16_t buf_sz,
                            uint32_t wait_ms) {
    VS_IOT_ASSERT(asav_res);

    uint16_t sz;
    return vs_sdmp_prvs_get(netif, mac, VS_PRVS_ASAV, (uint8_t *)asav_res, buf_sz, &sz, wait_ms);
}

/******************************************************************************/
vs_status_e
vs_sdmp_prvs_sign_data(const vs_netif_t *netif,
                       const vs_mac_addr_t *mac,
                       const uint8_t *data,
                       uint16_t data_sz,
                       uint8_t *signature,
                       uint16_t buf_sz,
                       uint16_t *signature_sz,
                       uint32_t wait_ms) {

    vs_status_e ret_code;
    VS_IOT_ASSERT(_prvs_impl.wait_func);

    _reset_last_result();

    // Send request
    STATUS_CHECK_RET(vs_sdmp_send_request(netif, mac, VS_PRVS_SERVICE_ID, VS_PRVS_ASGN, data, data_sz),
                     "Send request error");

    // Wait request
    _prvs_impl.wait_func(wait_ms, &_last_res, VS_CODE_ERR_PRVS_UNKNOWN);

    // Pass data
    if (VS_CODE_OK == _last_res && _last_data_sz <= buf_sz) {
        memcpy(signature, _last_data, _last_data_sz);
        *signature_sz = _last_data_sz;
        return VS_CODE_OK;
    }

    return VS_CODE_ERR_PRVS_UNKNOWN;
}

/******************************************************************************/
vs_status_e
vs_sdmp_prvs_set_tl_header(const vs_netif_t *netif,
                           const vs_mac_addr_t *mac,
                           const uint8_t *data,
                           uint16_t data_sz,
                           uint32_t wait_ms) {
    return vs_sdmp_prvs_set(netif, mac, VS_PRVS_TLH, data, data_sz, wait_ms);
}

/******************************************************************************/
vs_status_e
vs_sdmp_prvs_set_tl_footer(const vs_netif_t *netif,
                           const vs_mac_addr_t *mac,
                           const uint8_t *data,
                           uint16_t data_sz,
                           uint32_t wait_ms) {
    return vs_sdmp_prvs_set(netif, mac, VS_PRVS_TLF, data, data_sz, wait_ms);
}

/******************************************************************************/
