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

/*! \file snap.h
 * \brief SNAP network interface calls
 *
 * Secure Network Adjustable Protocol is used as transport layer for network communication. There are several layers
 * provided by Virgil IoT SDK that use this interface :
 * - PRVS : provision interface.
 * - FLDT : file data broadcast sent by server for clients to upgrade software. See #fldt_client_usage and
 * #fldt_server_usage for details
 * - INFO : devices information sent by clients for server to notify current software usage.
 *
 * \warning User has to provide network interface for #vs_snap_init call. As UDP broadcast example user can use
 * c-implementation tool.
 *
 * User can add his own protocols base on SNAP. It is necessary to provide service callbacks by filling
 * #vs_snap_service_t structure and register service by #vs_snap_register_service call.
 */

#ifndef AP_SECURITY_SDK_SNAP_H
#define AP_SECURITY_SDK_SNAP_H

#include <stdint.h>

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/status_code/status_code.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Init SNAP
 *
 * Initializes SNAP. Uses \a init call from #vs_netif_t network interface.
 * Must be called prior to any SNAP call.
 *
 * \param[in] default_netif Default network interface. Must not be NULL.
 * \param[in] packet_preprocessor_cb Packet preprocessor callback. May be NULL.
 * \param[in] manufacturer_id Manufacturer ID.
 * \param[in] device_type Device type.
 * \param[in] device_serial Device serial number.
 * \param[in] device_roles Device roles. Mask formed from vs_snap_device_role_e element.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_init(vs_netif_t *default_netif,
             vs_netif_process_cb_t packet_preprocessor_cb,
             const vs_device_manufacture_id_t manufacturer_id,
             const vs_device_type_t device_type,
             const vs_device_serial_t device_serial,
             uint32_t device_roles);

/** Destroy SNAP
 *
 * Uses \a deinit call from #vs_snap_service_t structure for each SNAP registered service and \a deinit call from
 * #vs_netif_t structure for network interface. \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_deinit();

/** Add network interface
 *
 * Adds network interface for SNAP. Uses \a init call from #vs_netif_t network interface.
 * Must be called after #vs_snap_init, but before any other SNAP call.
 * Pay attention to a maximum amount of network interfaces #VS_SNAP_NETIF_MAX
 *
 * \param[in] netif Network interface to be added. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_netif_add(vs_netif_t *netif);

vs_status_e
vs_snap_default_processor(vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);

/** Return current manufacture ID
 *
 * \return #vs_device_manufacture_id_t Manufacture ID. Cannot be NULL.
 */
const vs_device_manufacture_id_t *
vs_snap_device_manufacture(void);

/** Return current device type
 *
 * \return #vs_device_type_t Device type. Cannot be NULL.
 */
const vs_device_type_t *
vs_snap_device_type(void);

/** Return current device serial number
 *
 * \return #vs_device_serial_t Device serial number. Cannot be NULL.
 */
const vs_device_serial_t *
vs_snap_device_serial(void);

/** Return device role
 *
 * \return #Device roles mask formed from vs_device_serial_t elements.
 */
uint32_t
vs_snap_device_roles(void);

/** Return device network interface
 *
 * \return #vs_netif_t Device network interface. Cannot be NULL.
 */
const vs_netif_t *
vs_snap_default_netif(void);

/** Return device network interface constant for packet routing
 *
 * \return #vs_netif_t Device network interface. Cannot be NULL.
 */
const vs_netif_t *
vs_snap_netif_routing(void);

/** Send SNAP message
 *
 * Sends \a data message \a data_sz bytes length by using SNAP protocol specified by \a netif network interface.
 * \a tx callback from #vs_netif_t network interface is used.
 *
 * \param[in] netif Network interface. If NULL, default network interface specified by \a default_netif parameter for
 * #vs_snap_init call is used. \param[in] data Data buffer to be send. Must not be NULL. \param[in] data_sz Data size in
 * bytes to be send. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_send(const vs_netif_t *netif, const uint8_t *data, uint16_t data_sz);

/** Register SNAP service
 *
 * Initializes SNAP service.
 *
 * \param[in] service SNAP service descriptor. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_register_service(const vs_snap_service_t *service);

/** MAC address
 *
 * Returns \a mac_addr MAC address. Uses \a mac_addr call from #vs_netif_t network interface.
 *
 * \param[in] netif SNAP service descriptor. Must not be NULL.
 * \param[out] mac_addr Buffer to store MAC address. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_mac_addr(const vs_netif_t *netif, vs_mac_addr_t *mac_addr);

/** Return MAC address
 *
 * \return #vs_mac_addr_t MAC address.
 */
const vs_mac_addr_t *
vs_snap_broadcast_mac(void);

/** Prepare and send SNAP message
 *
 * Sends \a data message \a data_sz bytes length by using \a element_ID element of \a service_id SNAP service to \a mac
 * device by \a netif network interface.
 *
 * \param[in] netif Network interface. If NULL, default network interface specified by \a default_netif parameter for
 * #vs_snap_init call is used. \param[in] mac MAC address. If NULL, broadcast MAC address is used. \param[in] service_id
 * Service ID registered by #vs_snap_register_service call. \param[in] element_id Element ID of \a service_id.
 * \param[in] data Data buffer to be send. Must not be NULL.
 * \param[in] data_sz Data size in bytes to be send. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_send_request(const vs_netif_t *netif,
                     const vs_mac_addr_t *mac,
                     vs_snap_service_id_t service_id,
                     vs_snap_element_t element_id,
                     const uint8_t *data,
                     uint16_t data_sz);

/** Return SNAP statistics
 *
 * \return #vs_snap_stat_t Statistic data
 */
vs_snap_stat_t
vs_snap_get_statistics(void);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // AP_SECURITY_SDK_SNAP_H