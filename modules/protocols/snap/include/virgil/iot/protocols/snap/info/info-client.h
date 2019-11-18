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

/*! \file info-client.h
 * \brief INFO for client
 */
// TODO : examples!

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_INFO_CLIENT_H
#define VS_SECURITY_SDK_SNAP_SERVICES_INFO_CLIENT_H

#if INFO_CLIENT

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/snap/info/info-structs.h>
#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/status_code/status_code.h>

/** Wait callback
 *
 * \param[in] wait_ms
 * \param[in] condition
 * \param[in] idle
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_wait_t)(uint32_t wait_ms, int *condition, int idle);

// TODO : description???
/** Wait and stop callback
 *
 * \a stop_wait_func member or #vs_snap_prvs_client_impl_t structure.
 * \a wait_func member or #vs_snap_prvs_client_impl_t structure.
 *
 * \param[in] condition
 * \param[in] expect
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_stop_wait_t)(int *condition, int expect);

// TODO : description???
/** Start notification
 *
 * Sends notification with device information.
 *
 * \param[in] device #vs_snap_info_device_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_start_notif_cb_t)(vs_snap_info_device_t *device);

// TODO : description???
/** Device information
 *
 * Sends detailed device information.
 *
 * \param[in] general_info #vs_info_general_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_general_cb_t)(vs_info_general_t *general_info);

// TODO : description???
/** Statistics information
 *
 * Sends device statistic information.
 *
 * \param[in] statistics #vs_info_statistics_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_info_statistics_cb_t)(vs_info_statistics_t *statistics);

/** INFO client callbacks */
typedef struct {
    vs_snap_info_start_notif_cb_t device_start_cb; /**< Startup notification */
    vs_snap_info_general_cb_t general_info_cb;     /**< General information */
    vs_snap_info_statistics_cb_t statistics_cb;    /**< Device statistics */
} vs_snap_info_callbacks_t;

/** INFO Client SNAP Service implementation
 *
 * This call returns INFO client implementation. It must be called before any INFO call.
 *
 * \param[in] callbacks #vs_snap_info_callbacks_t callbacks. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
const vs_snap_service_t *
vs_snap_info_client(vs_snap_info_callbacks_t callbacks);

/** Enumerate devices
 *
 * \param[in] netif #vs_netif_t SNAP service descriptor. Must not be NULL.
 * \param[out] devices #vs_snap_info_device_t Devices information list. Must not be NULL.
 * \param[in] devices_max Maximum devices amount. Must not be zero.
 * \param[out] devices_cnt Buffer to store devices amount. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_info_enum_devices(const vs_netif_t *netif,
                          vs_snap_info_device_t *devices,
                          size_t devices_max,
                          size_t *devices_cnt,
                          uint32_t wait_ms);

// TODO : description??? fields???
/** Set pooling
 *
 * \param[in] netif #vs_netif_t SNAP service descriptor. Must not be NULL.
 * \param[in] mac #vs_mac_addr_t MAC address. Must not be NULL.
 * \param[in] elements Multiple #vs_snap_info_element_mask_e
 * \param[out] enable
 * \param[in] period_seconds
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_info_set_polling(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         uint32_t elements, // Multiple vs_snap_info_element_mask_e
                         bool enable,
                         uint16_t period_seconds);


#ifdef __cplusplus
}
#endif

#endif // INFO_CLIENT

#endif // VS_SECURITY_SDK_SNAP_SERVICES_INFO_CLIENT_H
