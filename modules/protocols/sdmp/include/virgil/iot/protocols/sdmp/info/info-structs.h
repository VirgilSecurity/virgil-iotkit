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

/*! \file info-structs.h
 * \brief INFO structures
 */

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_INFO_STRUCTS_H
#define VS_SECURITY_SDK_SDMP_SERVICES_INFO_STRUCTS_H

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/protocols/sdmp/sdmp-structs.h>

/** Device information
 *
 * Device information as parameter for #vs_sdmp_info_start_notif_cb_t call
 */
typedef struct {
    uint32_t device_roles; /**< Mask based on #vs_sdmp_device_role_e elements */
    uint8_t mac[ETH_ADDR_LEN]; /**< Device MAC address */
} vs_sdmp_info_device_t;

typedef struct {
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
    uint32_t build;
    uint32_t timestamp;
} vs_file_version_unpacked_t;

/** Device general information
 *
 * Device general information as parameter for #vs_sdmp_info_general_cb_t call
 */
typedef struct {
    uint8_t manufacture_id[VS_DEVICE_MANUFACTURE_ID_SIZE]; /**< Manufacture ID*/
    uint8_t device_type[VS_DEVICE_TYPE_SIZE]; /**< Device type */
    uint8_t default_netif_mac[ETH_ADDR_LEN]; /**< Default network interface MAC address*/
    uint32_t device_roles; /**< Mask based on #vs_sdmp_device_role_e elements */
    uint8_t fw_major; /**< Major version */
    uint8_t fw_minor; /**< Minor version */
    uint8_t fw_patch; /**< Patch version */
    uint8_t fw_dev_milestone; /**< Device milestone */
    uint8_t fw_dev_build; /**< Build number */
    uint32_t fw_timestamp; /**< The number of seconds elapsed since January 1, 2015 UTC */
    uint16_t tl_version; /**< Trust List version */
} vs_info_general_t;

/** Device statistics
 *
 * Device statistics as parameter for #vs_sdmp_info_statistics_cb_t call
 */
typedef struct {
    uint32_t sent;
    uint32_t received;
    uint8_t default_netif_mac[ETH_ADDR_LEN];
} vs_info_statistics_t;

// TODO : description???
/** Device statistics
 *
 * Element mask for #vs_sdmp_info_set_polling call
 */
typedef enum {
    VS_SDMP_INFO_GENERAL = HTONL_IN_COMPILE_TIME(0x0001),
    VS_SDMP_INFO_STATISTICS = HTONL_IN_COMPILE_TIME(0x0002),
} vs_sdmp_info_element_mask_e;

#endif // VS_SECURITY_SDK_SDMP_SERVICES_INFO_STRUCTS_H
