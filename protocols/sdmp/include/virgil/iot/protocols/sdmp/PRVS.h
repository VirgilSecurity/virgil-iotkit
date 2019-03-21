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

typedef enum {
    VS_PRVS_DNID = HTONL_IN_COMPILE_TIME('DNID'),	/**< Discover Not Initialized Devices */
    VS_PRVS_SGNP = HTONL_IN_COMPILE_TIME('SGNP'),	/**< Signature of own public key (by private key VS_PRVS_PBDM)  */
    VS_PRVS_PBR1 = HTONL_IN_COMPILE_TIME('PBR1'),	/**< Set Recovery Key 1 */
    VS_PRVS_PBR2 = HTONL_IN_COMPILE_TIME('PBR2'),	/**< Set Recovery Key 2 */
    VS_PRVS_PBA1 = HTONL_IN_COMPILE_TIME('PBA1'),	/**< Set Auth Key 1 */
    VS_PRVS_PBA2 = HTONL_IN_COMPILE_TIME('PBA2'),	/**< Set Auth Key 2 */
    VS_PRVS_PBT1 = HTONL_IN_COMPILE_TIME('PBT1'),	/**< Set Trust List Key 1 */
    VS_PRVS_PBT2 = HTONL_IN_COMPILE_TIME('PBT2'),	/**< Set Trust List 2 */
    VS_PRVS_PBF1 = HTONL_IN_COMPILE_TIME('PBF1'),   /**< Set Firmware Key 1 */
    VS_PRVS_PBF2 = HTONL_IN_COMPILE_TIME('PBF2'),   /**< Set Firmware Key 2 */
    VS_PRVS_TLH = HTONL_IN_COMPILE_TIME('_TLH'),	/**< Set Trust List header */
    VS_PRVS_TLC = HTONL_IN_COMPILE_TIME('_TLC'),	/**< Set Trust List chunk */
    VS_PRVS_TLF = HTONL_IN_COMPILE_TIME('_TLF'),	/**< Set Trust List footer */
} vs_sdmp_prvs_element_t;

typedef struct {
    vs_mac_addr_t mac_addr;
    uint8_t device_type;
    uint8_t reserved[10];
} vs_sdmp_prvs_dnid_element_t;

#define DNID_LIST_SZ_MAX (10)

typedef struct {
    vs_sdmp_prvs_dnid_element_t elements[DNID_LIST_SZ_MAX];
    size_t count;
} vs_sdmp_prvs_dnid_list_t;

typedef int (*vs_sdmp_prvs_dnid_t)();


// Get Service descriptor

const vs_sdmp_service_t *
vs_sdmp_prvs_service();

// HAL
int
vs_sdmp_prvs_configure_hal(vs_sdmp_prvs_dnid_t dnid_func);

// Commands
int
vs_sdmp_prvs_uninitialized_devices(const vs_netif_t *netif, vs_sdmp_prvs_dnid_list_t *list, size_t wait_ms);

int
vs_sdmp_prvs_device_info();

int
vs_sdmp_prvs_sign_data();

int
vs_sdmp_prvs_set(vs_sdmp_prvs_element_t element, const uint8_t *data, size_t data_sz);

int
vs_sdmp_prvs_get(vs_sdmp_prvs_element_t element, uint8_t *data, size_t buf_sz, size_t *data_sz);

#ifdef __cplusplus
}
#endif

#endif //KUNLUN_PRVS_H
