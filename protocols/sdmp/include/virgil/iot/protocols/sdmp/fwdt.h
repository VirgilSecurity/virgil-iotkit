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

#ifndef VIRGIL_SECURITY_SDK_SDMP_SERVICES_FWDT_H
#define VIRGIL_SECURITY_SDK_SDMP_SERVICES_FWDT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>

#define FWDT_LIST_SZ_MAX (50)
#define PUBKEY_MAX_SZ (100)

typedef enum {
    VS_FWDT_DNID = HTONL_IN_COMPILE_TIME('DNID'), /* Discover Not Initialized Devices */
} vs_sdmp_fwdt_element_e;

typedef struct {
    vs_mac_addr_t mac_addr;
    uint8_t device_type;
    uint8_t reserved[10];
} vs_sdmp_fwdt_dnid_element_t;

typedef struct {
    vs_sdmp_fwdt_dnid_element_t elements[FWDT_LIST_SZ_MAX];
    uint16_t count;
} vs_sdmp_fwdt_dnid_list_t;

typedef int (*vs_sdmp_fwdt_dnid_t)();
typedef int (*vs_sdmp_fwdt_stop_wait_t)(int *condition, int expect);
typedef int (*vs_sdmp_fwdt_wait_t)(uint32_t wait_ms, int *condition, int idle);

typedef struct {
    vs_sdmp_fwdt_dnid_t dnid_func;
    vs_sdmp_fwdt_stop_wait_t stop_wait_func;
    vs_sdmp_fwdt_wait_t wait_func;
} vs_sdmp_fwdt_impl_t;

// Get Service descriptor

const vs_sdmp_service_t *
vs_sdmp_fwdt_service();

// HAL
int
vs_sdmp_fwdt_configure_hal(vs_sdmp_fwdt_impl_t impl);

// Commands
int
vs_sdmp_fwdt_uninitialized_devices(const vs_netif_t *netif, vs_sdmp_fwdt_dnid_list_t *list, uint32_t wait_ms);

#ifdef __cplusplus
}
#endif

#endif // VIRGIL_SECURITY_SDK_SDMP_SERVICES_FWDT_H
