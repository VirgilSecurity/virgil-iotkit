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

/*! \file prvs-structs.h
 * \brief PRVS structures
 *
 * This file provides structures for PRVS service
 */

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_PRVS_STRUCTS_H
#define VS_SECURITY_SDK_SNAP_SERVICES_PRVS_STRUCTS_H

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/provision/provision-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#define DNID_LIST_SZ_MAX (50)
#define PUBKEY_MAX_SZ (100)

/** Device description
 *
 * Device description.
 *
 * This is response for #vs_snap_prvs_enum_devices call as an element from #vs_snap_prvs_dnid_list_t.
 */
typedef struct {
    vs_mac_addr_t mac_addr; /**< Device MAC address */
    uint32_t device_roles;  /**< Mask based on #vs_snap_device_role_e */
} vs_snap_prvs_dnid_element_t;

/** Devices enumeration
 *
 * The list of devices that have not been initialized.
 *
 * This is response for #vs_snap_prvs_enum_devices call.
 */
typedef struct {
    vs_snap_prvs_dnid_element_t elements[DNID_LIST_SZ_MAX]; /**< elements array */
    uint16_t count;                                         /**< elements amount */
} vs_snap_prvs_dnid_list_t;

/** Device information
 *
 * Device information.
 *
 * This is response for #vs_snap_prvs_device_info call.
 */
typedef struct __attribute__((__packed__)) {
    uint8_t manufacturer[VS_DEVICE_MANUFACTURE_ID_SIZE]; /**< manufacture ID */
    uint8_t device_type[VS_DEVICE_TYPE_SIZE];            /**< device type */
    uint8_t serial[VS_DEVICE_SERIAL_SIZE];               /**< device serial number */
    vs_mac_addr_t mac;                                   /**< device MAC address */
    uint16_t data_sz;                                    /**< \a data size */
    uint8_t data[];                                      /**< data : #vs_pubkey_t own key + #vs_sign_t signature */
} vs_snap_prvs_devi_t;

/** Signed data
 *
 * Signed data from #vs_snap_prvs_sign_data.
 */
typedef struct __attribute__((__packed__)) {
    uint8_t hash_type; /**< #vs_secmodule_hash_type_e */
    uint8_t data[];    /**< signed data */
} vs_snap_prvs_sgnp_req_t;

/** Provision stuff data
 *
 */
typedef struct __attribute__((__packed__)) {
    uint16_t request_id; /**< request id */
    uint8_t data[];      /**< request data */
} vs_snap_prvs_set_data_t;

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_SECURITY_SDK_SNAP_SERVICES_PRVS_STRUCTS_H
