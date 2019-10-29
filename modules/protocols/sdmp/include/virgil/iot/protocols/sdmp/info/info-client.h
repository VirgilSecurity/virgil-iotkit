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

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_INFO_CLIENT_H
#define VS_SECURITY_SDK_SDMP_SERVICES_INFO_CLIENT_H

#if INFO_CLIENT

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/info/info-structs.h>
#include <virgil/iot/protocols/sdmp/sdmp-structs.h>
#include <virgil/iot/status_code/status_code.h>

/** Wait callback
 *
 * \param[in] wait_ms
 * \param[in] condition
 * \param[in] idle
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_sdmp_info_wait_t)(uint32_t wait_ms, int *condition, int idle);

// TODO : description???
/** Wait and stop callback
 *
 * \a stop_wait_func member or #vs_sdmp_prvs_client_impl_t structure.
 * \a wait_func member or #vs_sdmp_prvs_client_impl_t structure.
 *
 * \param[in] condition
 * \param[in] expect
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_sdmp_info_stop_wait_t)(int *condition, int expect);

// TODO : description???
/** Start notification
 *
 * Sends notification with device information.
 *
 * \param[in] device #vs_sdmp_info_device_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_sdmp_info_start_notif_cb_t)(vs_sdmp_info_device_t *device);

// TODO : description???
/** Device information
 *
 * Sends detailed device information.
 *
 * \param[in] general_info #vs_info_general_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_sdmp_info_general_cb_t)(vs_info_general_t *general_info);

// TODO : description???
/** Statistics information
 *
 * Sends device statistic information.
 *
 * \param[in] statistics #vs_info_statistics_t device information.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_sdmp_info_statistics_cb_t)(vs_info_statistics_t *statistics);

// TODO : description???
/** INFO client callbacks
 *
 * INFO client callbacks for #vs_sdmp_info_client call.
 *
 * \param[in] device_start_cb #vs_sdmp_info_start_notif_cb_t startup notification.
 * \param[in] general_info_cb #vs_sdmp_info_general_cb_t general information.
 * \param[in] statistics_cb #vs_sdmp_info_statistics_cb_t device statistics.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef struct {
    vs_sdmp_info_start_notif_cb_t device_start_cb;
    vs_sdmp_info_general_cb_t general_info_cb;
    vs_sdmp_info_statistics_cb_t statistics_cb;
} vs_sdmp_info_callbacks_t;

// TODO : members description???
/** INFO client implementation
 */
typedef struct {
    vs_sdmp_info_wait_t wait_func; /**< Wait function callback */
    vs_sdmp_info_stop_wait_t stop_wait_func; /**< Stop and wait function callback */
} vs_sdmp_info_impl_t;

/** INFO Client SDMP Service implementation
 *
 * This call returns INFO client implementation. It must be called before any INFO call.
 *
 * \param[in] impl #vs_sdmp_info_impl_t SDMP implementation. Must not be NULL.
 * \param[in] callbacks #vs_sdmp_info_callbacks_t callbacks. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
const vs_sdmp_service_t *
vs_sdmp_info_client(vs_sdmp_info_impl_t impl, vs_sdmp_info_callbacks_t callbacks);

/** Enumerate devices
 *
 * \param[in] netif #vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[out] devices #vs_sdmp_info_device_t Devices information list. Must not be NULL.
 * \param[in] devices_max Maximum devices amount. Must not be zero.
 * \param[out] devices_cnt Buffer to store devices amount. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_info_enum_devices(const vs_netif_t *netif,
                          vs_sdmp_info_device_t *devices,
                          size_t devices_max,
                          size_t *devices_cnt,
                          uint32_t wait_ms);

// TODO : description??? fields???
/** Set pooling
 *
 * \param[in] netif #vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[in] mac #vs_mac_addr_t MAC address. Must not be NULL.
 * \param[in] elements Multiple #vs_sdmp_info_element_mask_e
 * \param[out] enable
 * \param[in] period_seconds
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_info_set_polling(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         uint32_t elements, // Multiple vs_sdmp_info_element_mask_e
                         bool enable,
                         uint16_t period_seconds);


#ifdef __cplusplus
}
#endif

#endif // INFO_CLIENT

#endif // VS_SECURITY_SDK_SDMP_SERVICES_INFO_CLIENT_H
