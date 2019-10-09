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

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_PRVS_STRUCTS_H
#define VS_SECURITY_SDK_SDMP_SERVICES_PRVS_STRUCTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/provision/provision.h>

#define DNID_LIST_SZ_MAX (50)
#define PUBKEY_MAX_SZ (100)

typedef struct {
    vs_mac_addr_t mac_addr;
    uint32_t device_roles; // vs_sdmp_device_role_e
} vs_sdmp_prvs_dnid_element_t;

typedef struct {
    vs_sdmp_prvs_dnid_element_t elements[DNID_LIST_SZ_MAX];
    uint16_t count;
} vs_sdmp_prvs_dnid_list_t;

typedef struct __attribute__((__packed__)) {
    uint8_t manufacturer[VS_DEVICE_MANUFACTURE_ID_SIZE];
    uint8_t device_type[VS_DEVICE_DEVICE_TYPE_SIZE];
    uint8_t serial[VS_DEVICE_SERIAL_SIZE];
    vs_mac_addr_t mac;
    uint16_t data_sz;

    uint8_t data[]; // vs_pubkey_t own_key + vs_sign_t signature
} vs_sdmp_prvs_devi_t;

typedef struct __attribute__((__packed__)) {
    uint8_t hash_type; // vs_hsm_hash_type_e
    uint8_t data[];
} vs_sdmp_prvs_sgnp_req_t;

typedef bool (*vs_sdmp_prvs_dnid_t)(void);
typedef vs_status_e (*vs_sdmp_prvs_save_data_t)(vs_sdmp_prvs_element_e element_id,
                                                const uint8_t *data,
                                                uint16_t data_sz);

typedef vs_status_e (*vs_sdmp_prvs_load_data_t)();
typedef vs_status_e (*vs_sdmp_prvs_device_info_t)(vs_sdmp_prvs_devi_t *device_info, uint16_t buf_sz);
typedef vs_status_e (*vs_sdmp_prvs_finalize_storage_t)(vs_pubkey_t *asav_response, uint16_t *resp_sz);
typedef vs_status_e (*vs_sdmp_prvs_start_save_tl_t)(const uint8_t *data, uint16_t data_sz);
typedef vs_status_e (*vs_sdmp_prvs_save_tl_part_t)(const uint8_t *data, uint16_t data_sz);
typedef vs_status_e (*vs_sdmp_prvs_finalize_tl_t)(const uint8_t *data, uint16_t data_sz);
typedef vs_status_e (*vs_sdmp_prvs_stop_wait_t)(int *condition, int expect);
typedef vs_status_e (*vs_sdmp_prvs_wait_t)(uint32_t wait_ms, int *condition, int idle);
typedef vs_status_e (*vs_sdmp_sign_data_t)(const uint8_t *data,
                                           uint16_t data_sz,
                                           uint8_t *signature,
                                           uint16_t buf_sz,
                                           uint16_t *signature_sz);

typedef struct {
    vs_sdmp_prvs_dnid_t is_initialized_func;
    vs_sdmp_prvs_save_data_t save_data_func;
    vs_sdmp_prvs_load_data_t load_data_func;
    vs_sdmp_prvs_device_info_t device_info_func;
    vs_sdmp_prvs_finalize_storage_t finalize_storage_func;
    vs_sdmp_prvs_start_save_tl_t start_save_tl_func;
    vs_sdmp_prvs_save_tl_part_t save_tl_part_func;
    vs_sdmp_prvs_finalize_tl_t finalize_tl_func;
    vs_sdmp_sign_data_t sign_data_func;
    vs_sdmp_prvs_stop_wait_t stop_wait_func;
    vs_sdmp_prvs_wait_t wait_func;
} vs_sdmp_prvs_impl_t;

#ifdef __cplusplus
}
#endif

#endif // VS_SECURITY_SDK_SDMP_SERVICES_PRVS_STRUCTS_H
