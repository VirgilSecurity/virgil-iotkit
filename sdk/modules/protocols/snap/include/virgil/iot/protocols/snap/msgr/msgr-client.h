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

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_MSGR_CLIENT_H
#define VS_SECURITY_SDK_SNAP_SERVICES_MSGR_CLIENT_H

#if MSGR_CLIENT

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/msgr/msgr-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Startup notification
 *
 * Sends startup notification with remote device information.
 *
 * \param[in] device #vs_snap_msgr_device_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_msgr_start_notif_cb_t)(vs_snap_msgr_device_t *device);

/** Get data from a remote device
 *
 * This function is called by receiving response to get actual data from a remote device
 * or a periodical VS_MSGR_STAT request with actual data.
 *
 * \param[out] data Output buffer to store data. Must not be NULL.
 * \param[in] buf_sz Buffer size. Must not be zero.
 * \param[out] data_sz Pointer to save stored data size. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_msgr_device_data_cb_t)(uint8_t *data, uint32_t data_sz);

/** MSGR client implementations
 *
 * \note Any callback can be NULL. In this case, there will be no actions with requests.
 *
 */
typedef struct {
    vs_snap_msgr_start_notif_cb_t device_start; /**< Startup notification */
    vs_snap_msgr_device_data_cb_t device_data;  /**< Process received data from a device */
} vs_snap_msgr_client_service_t;

/** Enumerate remote devices, which support msgr service
 *
 * This call enumerates all devices present in the current network. It waits for \a wait_ms and returns collected
 * information.
 *
 * \param[in] netif #vs_netif_t SNAP service descriptor. If NULL, default one will be used.
 * \param[out] devices #vs_snap_msgr_device_t Devices information list. Must not be NULL.
 * \param[in] devices_max Maximum devices amount. Must not be zero.
 * \param[out] devices_cnt Buffer to store devices amount. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_msgr_enum_devices(const vs_netif_t *netif,
                          vs_snap_msgr_device_t *devices,
                          size_t devices_max,
                          size_t *devices_cnt,
                          uint32_t wait_ms);

/** Set polling
 *
 * This call enables or disables polling data from remote devices
 *
 * \param[in] netif #vs_netif_t SNAP service descriptor. If NULL, default one will be used.
 * \param[in] mac #vs_mac_addr_t MAC address. Must not be NULL.
 * \param[out] enable Enable or disable \a elements to be sent.
 * \param[in] period_seconds Period in seconds for statistics sending
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_snap_msgr_set_polling(const vs_netif_t *netif, const vs_mac_addr_t *mac, bool enable, uint16_t period_seconds);

/** MSGR Client SNAP Service implementation
 *
 * This call returns MSGR client implementation. It must be called before any MSGR call.
 *
 * \param[in] impl Snap MSGR Client functions implementation.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
const vs_snap_service_t *
vs_snap_msgr_client(vs_snap_msgr_client_service_t impl);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // MSGR_CLIENT
#endif // VS_SECURITY_SDK_SNAP_SERVICES_MSGR_CLIENT_H
