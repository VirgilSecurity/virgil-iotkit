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

/*! \file info-client.h
 * \brief INFO for client
 *
 * INFO service is used to provide information about current device state in the local network. Network
 * in this case is limited by SNAP transport protocol.
 *
 * In INFO meaning "Server" is any functional device. "Client" is the special device for statistic collection only.
 * It can be any server PC or MCU device. Servers send their statistic information by startup. Also client can request
 * periodical state sending by polling request.
 *
 * Virgil IoT KIT provides client example as virgil-snapd application.
 *
 * \section info_client_usage INFO Client usage
 *
 * Before first INFO calls usage it is necessary to register INFO Client service :
 *
 * \code
 *
 *     const vs_snap_service_t *snap_info_client;     // INFO service
 *     vs_snap_info_device_t devices[100];            // Devices list. Assuming 100 devices in the list is enough
 *     const size_t devices_max = sizeof(devices) / sizeof(devices[0]);   // Maximum devices in the list
 *     size_t devices_amount = 0;                     // Enumerates devices amount
 *     uint32_t wait_ms = 3000;                       // Waiting 3 seconds for all devices enumerating
 *     vs_mac_addr_t own_mac;                         // Own MAC address
 *     uint16_t poll_period_sec = 1;                  // Send statistics each second
 *
 *     // Initialize own_mac
 *
 *     // Register INFO Client service
 *     snap_info_client = vs_snap_info_client(_info_client_impl());
 *     STATUS_CHECK(vs_snap_register_service(snap_info_client), "Cannot register INFO Сlient service");
 *
 *     // Enumerate devices
 *     STATUS_CHECK(vs_snap_info_enum_devices(NULL, devices, devices_max, &devices_amount, wait_ms),
 *        "Unable to enumerate devices in the network");
 *
 *     // Request periodical state sending for all parameters
 *     STATUS_CHECK(vs_snap_info_set_polling(NULL, &own_mac, VS_SNAP_INFO_GENERAL | VS_SNAP_INFO_STATISTICS, true,
 *        poll_period_sec), "Unable to request periodical polling sends");
 *
 * \endcode
 *
 * own_mac is initialized by current device MAC address. It can be provided by #vs_snap_mac_addr call.
 *
 * #vs_snap_info_client receives structure with notification implementations :
 *
 * \note All callbacks can be NULL.
 *
 * \code
 *
 * vs_status_e
 * _device_start_impl(vs_snap_info_device_t *device) {
 *      // Process startup notification
 *  }
 *
 * vs_status_e
 * _general_info_impl(vs_info_general_t *general_info) {
 *      // Process general device information
 *  }
 *
 * vs_status_e
 * _statistics_impl(vs_info_statistics_t *statistics) {
 *      // Process device statistics
 *  }

 * vs_snap_info_client_service_t
 * _info_client_impl() {
 *      vs_snap_info_client_service_t impl;
 *      impl.device_start = _device_start_impl;
 *      impl.general_info = _general_info_impl;
 *      impl.statistics = _statistics_impl;
 * }
 *
 * \endcode
 *
 * Polling is started by #vs_snap_info_set_polling request with \a enable = true. \a enable = false removes specified
 * statistic element specified by \a elements mask.
 *
 */

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_INFO_CLIENT_H
#define VS_SECURITY_SDK_SNAP_SERVICES_INFO_CLIENT_H

#if INFO_CLIENT

#include <virgil/iot/protocols/snap/info/info-structs.h>
#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/status_code/status_code.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Wait implementation
 *
 * \param[in] wait_ms
 * \param[in] condition
 * \param[in] idle
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_wait_t)(uint32_t wait_ms, int *condition, int idle);

/** Wait and stop callback
 *
 * \param[in] condition
 * \param[in] expect
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_stop_wait_t)(int *condition, int expect);

/** Start notification request
 *
 * This function is called by receiving startup notification from device.
 *
 * \param[in] device Device statical information. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_start_notif_cb_t)(vs_snap_info_device_t *device);

/** General device information request
 *
 * This function is called by receiving general device information.
 *
 * General device information polling is started by #vs_snap_info_set_polling call when \a elements contains
 * VS_SNAP_INFO_GENERAL bit.
 *
 * \param[in] general_info Device general information. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_general_cb_t)(vs_info_general_t *general_info);

/** Device statistics request
 *
 * This function is called by receiving device statistics.
 *
 * General device information polling is started by #vs_snap_info_set_polling call when \a elements contains
 * VS_SNAP_INFO_STATISTICS bit.
 *
 * \param[in] statistics Device statistics. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_statistics_cb_t)(vs_info_statistics_t *statistics);

/** INFO client implementations
 *
 * \note Any callback can be NULL. In this case standard flow will be used.
 *
 */
typedef struct {
    vs_snap_info_start_notif_cb_t device_start; /**< Startup notification */
    vs_snap_info_general_cb_t general_info;     /**< General information */
    vs_snap_info_statistics_cb_t statistics;    /**< Device statistics */
} vs_snap_info_client_service_t;

/** INFO Client SNAP Service implementation
 *
 * This call returns INFO client implementation. It must be called before any INFO call.
 *
 * \param[in] impl Snap Info Client functions implementation.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
const vs_snap_service_t *
vs_snap_info_client(vs_snap_info_client_service_t impl);

/** Enumerate devices
 *
 * This call enumerates all devices present in the current network. It waits for \a wait_ms and returns collected
 * information.
 *
 * \param[in] netif #vs_netif_t SNAP service descriptor. If NULL, default one will be used.
 * \param[out] devices #vs_snap_info_device_t Devices information list. Must not be NULL.
 * \param[in] devices_max Maximum devices amount. Must not be zero.
 * \param[out] devices_cnt Buffer to store devices amount. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_info_enum_devices(const vs_netif_t *netif,
                          vs_snap_info_device_t *devices,
                          size_t devices_max,
                          size_t *devices_cnt,
                          uint32_t wait_ms);

/** Set polling
 *
 * This call enables or disables polling for elements masked in \a elements field that contains mask  with
 * #vs_snap_info_element_mask_e fields.
 *
 * \param[in] netif #vs_netif_t SNAP service descriptor. If NULL, default one will be used.
 * \param[in] mac #vs_mac_addr_t MAC address. Must not be NULL.
 * \param[in] elements #vs_snap_info_element_mask_e mask.
 * \param[out] enable Enable or disable \a elements to be sent.
 * \param[in] period_seconds Period in seconds for statistics sending
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_info_set_polling(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         uint32_t elements,
                         bool enable,
                         uint16_t period_seconds);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // INFO_CLIENT

#endif // VS_SECURITY_SDK_SNAP_SERVICES_INFO_CLIENT_H
