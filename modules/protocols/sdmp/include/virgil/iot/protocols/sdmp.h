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

/*! \file sdmp.h
 * \brief SDMP network interface calls
 *
 * SDMP protocol is used as transport layer for network communication. There are several layers provided by Virgil IoT SDK that use this interface :
 * - PRVS : provision interface.
 * - FLDT : file data broadcast sent by server for clients to upgrade software. See \ref fldt_client_usage and \ref fldt_server_usage for details
 * - INFO : devices information sent by clients for server to notify current software usage.
 *
 * User can add his own protocols base on SDMP. It is necessary to provide service callbacks by filling \ref vs_sdmp_service_t structure and register service by \ref vs_sdmp_register_service call.
 */
// TODO : add an example of SDMP service registration

#include <stdint.h>

#include <virgil/iot/protocols/sdmp/sdmp-structs.h>
#include <virgil/iot/status_code/status_code.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Init SDMP
 *
 * Initializes SDMP. Uses \a init call from \ref vs_netif_t network interface.
 * Must be called prior to any SDMP call.
 *
 * \param[in] default_netif \ref vs_netif_t Default network interface. Must not be NULL.
 * \param[in] manufacturer_id \ref vs_device_manufacture_id_t Manufacturer ID.
 * \param[in] device_type \ref vs_device_type_t Device type.
 * \param[in] device_serial \ref vs_device_serial_t Device serial number.
 * \param[in] device_roles \ref Device roles. Mask formed from vs_sdmp_device_role_e element.
 *
 * \return \ref vs_status_e \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_sdmp_init(vs_netif_t *default_netif,
             const vs_device_manufacture_id_t manufacturer_id,
             const vs_device_type_t device_type,
             const vs_device_serial_t device_serial,
             uint32_t device_roles);

/** Destroy SDMP
 *
 * Uses \a deinit call from \ref vs_sdmp_service_t structure for each SDMP registered service and \a deinit call from \ref vs_netif_t structure for network interface.
 * \return \ref vs_status_e \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_sdmp_deinit();

/** Return current manufacture ID
 *
 * \return \ref vs_device_manufacture_id_t Manufacture ID. Cannot be NULL.
 */
const vs_device_manufacture_id_t *
vs_sdmp_device_manufacture(void);

/** Return current device type
 *
 * \return \ref vs_device_type_t Device type. Cannot be NULL.
 */
const vs_device_type_t *
vs_sdmp_device_type(void);

/** Return current device serial number
 *
 * \return \ref vs_device_serial_t Device serial number. Cannot be NULL.
 */
const vs_device_serial_t *
vs_sdmp_device_serial(void);

/** Return device role
 *
 * \return \ref Device roles mask formed from vs_device_serial_t elements.
 */
uint32_t
vs_sdmp_device_roles(void);

// TODO : remove?..
#if 0
vs_status_e
vs_sdmp_add_netif(const vs_netif_t *netif);
#endif

/** Return device role
 *
 * \return \ref vs_device_serial_t Device serial number. Cannot be NULL.
 */
const vs_netif_t *
vs_sdmp_default_netif(void);

/** Send SDMP message
 *
 * Sends \a data message \a data_sz bytes length by using SDMP protocol specified by \a netif network interface.
 * \a tx callback from \ref vs_netif_t network interface is used.
 *
 * \param[in] netif \ref vs_netif_t Network interface. If NULL, default network interface specified by \a default_netif parameter for \ref vs_sdmp_init call is used.
 * \param[in] data Data buffer to be send. Must not be NULL.
 * \param[in] data_sz Data size in bytes to be send. Must not be zero.
 *
 * \return \ref vs_status_e \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_sdmp_send(const vs_netif_t *netif, const uint8_t *data, uint16_t data_sz);

/** Register SDMP service
 *
 * Initializes \a service SDMP service.
 *
 * \param[in] service \ref vs_sdmp_service_t SDMP service descriptor. Must not be NULL.
 *
 * \return \ref vs_status_e \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_sdmp_register_service(const vs_sdmp_service_t *service);

/** MAC address
 *
 * Returns \a mac_addr MAC address. Uses \a mac_addr call from \ref vs_netif_t network interface.
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[out] mac_addr \ref vs_mac_addr_t Buffer to store MAC address. Must not be NULL.
 *
 * \return \ref vs_status_e \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_sdmp_mac_addr(const vs_netif_t *netif, vs_mac_addr_t *mac_addr);

/** Return MAC address
 *
 * \return \ref vs_mac_addr_t MAC address.
 */
const vs_mac_addr_t *
vs_sdmp_broadcast_mac(void);

/** Prepare and send SDMP message
 *
 * Sends \a data message \a data_sz bytes length by using \a element_ID element of \a service_id SDMP service to \a mac device by \a netif network interface.
 *
 * \param[in] netif \ref vs_netif_t Network interface. If NULL, default network interface specified by \a default_netif parameter for \ref vs_sdmp_init call is used.
 * \param[in] mac \ref vs_mac_addr_t MAC address. If NULL, broadcast MAC address is used.
 * \param[in] service_id \ref vs_sdmp_service_id_t Service ID registered by \ref vs_sdmp_register_service call.
 * \param[in] element_id \ref vs_sdmp_element_t Element ID of \a service_id.
 * \param[in] data Data buffer to be send. Must not be NULL.
 * \param[in] data_sz Data size in bytes to be send. Must not be zero.
 *
 * \return \ref vs_status_e \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_sdmp_send_request(const vs_netif_t *netif,
                     const vs_mac_addr_t *mac,
                     vs_sdmp_service_id_t service_id,
                     vs_sdmp_element_t element_id,
                     const uint8_t *data,
                     uint16_t data_sz);

/** Return SDMP statistics
 *
 * \return \ref vs_sdmp_stat_t Statistic data
 */
vs_sdmp_stat_t
vs_sdmp_get_statistics(void);

#ifdef __cplusplus
}
#endif