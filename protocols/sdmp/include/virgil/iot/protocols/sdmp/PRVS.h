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

#ifndef KUNLUN_PRVS_H
#define KUNLUN_PRVS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>

#define DNID_LIST_SZ_MAX (50)
#define PUBKEY_MAX_SZ (100)

typedef enum {
    VS_PRVS_DNID = HTONL_IN_COMPILE_TIME('DNID'), /**< Discover Not Initialized Devices */
    VS_PRVS_SGNP = HTONL_IN_COMPILE_TIME('SGNP'), /**< Signature of own public key (by private key VS_PRVS_PBDM)  */
    VS_PRVS_PBR1 = HTONL_IN_COMPILE_TIME('PBR1'), /**< Set Recovery Key 1 */
    VS_PRVS_PBR2 = HTONL_IN_COMPILE_TIME('PBR2'), /**< Set Recovery Key 2 */
    VS_PRVS_PBA1 = HTONL_IN_COMPILE_TIME('PBA1'), /**< Set Auth Key 1 */
    VS_PRVS_PBA2 = HTONL_IN_COMPILE_TIME('PBA2'), /**< Set Auth Key 2 */
    VS_PRVS_PBT1 = HTONL_IN_COMPILE_TIME('PBT1'), /**< Set Trust List Key 1 */
    VS_PRVS_PBT2 = HTONL_IN_COMPILE_TIME('PBT2'), /**< Set Trust List 2 */
    VS_PRVS_PBF1 = HTONL_IN_COMPILE_TIME('PBF1'), /**< Set Firmware Key 1 */
    VS_PRVS_PBF2 = HTONL_IN_COMPILE_TIME('PBF2'), /**< Set Firmware Key 2 */
    VS_PRVS_TLH = HTONL_IN_COMPILE_TIME('_TLH'),  /**< Set Trust List Header */
    VS_PRVS_TLC = HTONL_IN_COMPILE_TIME('_TLC'),  /**< Set Trust List Chunk */
    VS_PRVS_TLF = HTONL_IN_COMPILE_TIME('_TLF'),  /**< Set Trust List Footer */
    VS_PRVS_DEVI = HTONL_IN_COMPILE_TIME('DEVI'), /**< Get DEVice Info */
    VS_PRVS_ASAV = HTONL_IN_COMPILE_TIME('ASAV'), /**< Action SAVe provision */
    VS_PRVS_ASGN = HTONL_IN_COMPILE_TIME('ASGN'), /**< Action SiGN data */
} vs_sdmp_prvs_element_t;

typedef struct {
    vs_mac_addr_t mac_addr;
    uint8_t device_type;
    uint8_t reserved[10];
} vs_sdmp_prvs_dnid_element_t;

typedef struct {
    vs_sdmp_prvs_dnid_element_t elements[DNID_LIST_SZ_MAX];
    size_t count;
} vs_sdmp_prvs_dnid_list_t;

typedef struct __attribute__((__packed__)) {
    uint16_t id;
    uint8_t val_sz;
    uint8_t val[];
} vs_sdmp_prvs_signature_t;

typedef struct __attribute__((__packed__)) {
    uint8_t pubkey[PUBKEY_MAX_SZ];
    uint8_t pubkey_sz;
} vs_sdmp_pubkey_t;

typedef struct __attribute__((__packed__)) {
    uint32_t manufacturer;
    uint32_t model;
    vs_mac_addr_t mac;
    uint8_t udid_of_device[32];

    vs_sdmp_pubkey_t own_key;
    vs_sdmp_prvs_signature_t signature;
} vs_sdmp_prvs_devi_t;

typedef int (*vs_sdmp_prvs_dnid_t)();
typedef int (*vs_sdmp_prvs_save_data_t)(vs_sdmp_prvs_element_t element_id, const uint8_t *data, size_t data_sz);
typedef int (*vs_sdmp_prvs_load_data_t)();
typedef int (*vs_sdmp_prvs_device_info_t)(vs_sdmp_prvs_devi_t *device_info, size_t buf_sz);
typedef int (*vs_sdmp_prvs_finalize_storage_t)(vs_sdmp_pubkey_t *asav_response);
typedef int (*vs_sdmp_prvs_start_save_tl_t)(const uint8_t *data, size_t data_sz);
typedef int (*vs_sdmp_prvs_save_tl_part_t)(const uint8_t *data, size_t data_sz);
typedef int (*vs_sdmp_prvs_finalize_tl_t)(const uint8_t *data, size_t data_sz);
typedef int (*vs_sdmp_sign_data_t)(const uint8_t *data,
                                   size_t data_sz,
                                   uint8_t *signature,
                                   size_t buf_sz,
                                   size_t *signature_sz);

typedef struct {
    vs_sdmp_prvs_dnid_t dnid_func;
    vs_sdmp_prvs_save_data_t save_data_func;
    vs_sdmp_prvs_load_data_t load_data_func;
    vs_sdmp_prvs_device_info_t device_info_func;
    vs_sdmp_prvs_finalize_storage_t finalize_storage_func;
    vs_sdmp_prvs_start_save_tl_t start_save_tl_func;
    vs_sdmp_prvs_save_tl_part_t save_tl_part_func;
    vs_sdmp_prvs_finalize_tl_t finalize_tl_func;
    vs_sdmp_sign_data_t sign_data_func;
} vs_sdmp_prvs_impl_t;

// Get Service descriptor

const vs_sdmp_service_t *
vs_sdmp_prvs_service();

// HAL
int
vs_sdmp_prvs_configure_hal(vs_sdmp_prvs_impl_t impl);

// Commands
int
vs_sdmp_prvs_uninitialized_devices(const vs_netif_t *netif, vs_sdmp_prvs_dnid_list_t *list, size_t wait_ms);

int
vs_sdmp_prvs_save_provision(const vs_netif_t *netif,
                            const vs_mac_addr_t *mac,
                            vs_sdmp_pubkey_t *asav_res,
                            size_t wait_ms);

int
vs_sdmp_prvs_device_info(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_sdmp_prvs_devi_t *device_info,
                         size_t buf_sz,
                         size_t wait_ms);

int
vs_sdmp_prvs_sign_data(const vs_netif_t *netif,
                       const vs_mac_addr_t *mac,
                       const uint8_t *data,
                       size_t data_sz,
                       uint8_t *signature,
                       size_t buf_sz,
                       size_t *signature_sz,
                       size_t wait_ms);

int
vs_sdmp_prvs_set(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_sdmp_prvs_element_t element,
                 const uint8_t *data,
                 size_t data_sz,
                 size_t wait_ms);

int
vs_sdmp_prvs_get(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_sdmp_prvs_element_t element,
                 uint8_t *data,
                 size_t buf_sz,
                 size_t *data_sz,
                 size_t wait_ms);

int
vs_sdmp_prvs_finalize_tl(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         const uint8_t *data,
                         size_t data_sz,
                         size_t wait_ms);

#ifdef __cplusplus
}
#endif

#endif // KUNLUN_PRVS_H
