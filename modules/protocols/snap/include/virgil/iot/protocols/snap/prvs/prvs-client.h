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

/*! \file prvs-client.h
 * \brief PRVS for client
 *
 * PRVS is the provision service. PRVS Server is a device, PRVS Client is the factory server with factory initializer
 * utility. Client prepares device's card, server signs it, and client saves this information.
 *
 * \section prvs_client_usage PRVS Client usage
 *
 * Before first call it is necessary to register PRVS service :
 *
 * \code
 *    const vs_snap_service_t *snap_prvs_client;      // INFO service
 *    vs_snap_prvs_dnid_list_t dnid_list;             // Array of "Do Not Initialized Devices"
 *    uint32_t wait_ms = 3000;                        // Waiting 3 seconds for all devices enumerating
 *
 *    // Initialize snap_prvs_client
 *
 *    // Register PRVS Client service
 *    snap_prvs_client = vs_snap_prvs_client(_snap_prvs_impl());
 *    STATUS_CHECK(vs_snap_register_service(snap_prvs_client), "Cannot register PRVS client service");
 *
 *    // Enumerate uninitialized devices
 *    STATUS_CHECK(vs_snap_prvs_enum_devices(NULL, &dnid_list, devices_max, &devices_amount, wait_ms),
 *        "Unable to enumerate devices without provision");
 *
 * \endcode
 *
 * \a _snap_prvs_impl is the function that returns implementation for #vs_snap_prvs_client_impl_t. It requires two
 * function to be present - #vs_snap_prvs_stop_wait_t and #vs_snap_prvs_wait_t. You can find an example of their
 * implementation in the c-implementation tool.
 *
 * \note Almost all calls have \a netif parameter. If it is null, SNAP interface that has been initialized will be used.
 * It is OK for default case.
 */

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_PRVS_CLIENT_H
#define VS_SECURITY_SDK_SNAP_SERVICES_PRVS_CLIENT_H

#if PRVS_CLIENT

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/prvs/prvs-structs.h>
#include <virgil/iot/provision/provision-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Stop waiting implementation
 *
 * This function interrupts asynchronously waiting started by #wait_func and sets for \a condition the value \expect
 *
 * \a stop_wait_func member or #vs_snap_prvs_client_impl_t structure.
 * \a wait_func member or #vs_snap_prvs_client_impl_t structure.
 *
 * \param[in] condition Condition buffer. Must not be NULL.
 * \param[in] expect Expected value to be set.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_prvs_stop_wait_t)(int *condition, int expect);

/** Wait implementation
 *
 * This function checks \a condition variable during \a wait_ms when it will be equal to the \a idle condition
 *
 * \param[in] wait_ms Wait in milliseconds.
 * \param[in] condition Condition buffer. Must not be NULL.
 * \param[in] idle Idle condition.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_prvs_wait_t)(uint32_t wait_ms, int *condition, int idle);

/** PRVS client implementation */
typedef struct {
    vs_snap_prvs_stop_wait_t stop_wait_func; /**< Stop waiting implementation */
    vs_snap_prvs_wait_t wait_func;           /**< Wait implementation */
} vs_snap_prvs_client_impl_t;

/** PRVS Client SNAP Service implementation
 *
 * This call returns PRVS client implementation. It must be called before any PRVS call.
 *
 * \param[in] impl #vs_snap_prvs_client_impl_t callback functions. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
const vs_snap_service_t *
vs_snap_prvs_client(vs_snap_prvs_client_impl_t impl);

/** Enumerate devices, which don't have initialization provision yet
 *
 * Enumerate devices, which don't have initialization provision yet.
 *
 * \param[in] netif #vs_netif_t SNAP service descriptor. Must not be NULL.
 * \param[out] list #vs_snap_prvs_dnid_list_t Buffer with devices list. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_prvs_enum_devices(const vs_netif_t *netif, vs_snap_prvs_dnid_list_t *list, uint32_t wait_ms);

/** Save provision
 *
 * Sends request to initialize security module and to generate device key pair. After it necessarily saves the own key
 * pair and received Recovery keys to OTP memory.
 *
 * \param[in] netif SNAP service descriptor. Must not be NULL.
 * \param[in] mac Device MAC address.
 * \param[out] asav_res #vs_pubkey_t buffer to be saved.
 * \param[in] buf_sz Buffer size
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_prvs_save_provision(const vs_netif_t *netif,
                            const vs_mac_addr_t *mac,
                            uint8_t *asav_res,
                            uint16_t buf_sz,
                            uint32_t wait_ms);

/** Request device information
 *
 * Sends request for device information.
 *
 * \param[in] netif SNAP service descriptor. If NULL, default one will be used.
 * \param[in] mac Device MAC address.
 * \param[out] device_info Device information output buffer. Must not be NULL.
 * \param[in] buf_sz Buffer size
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_prvs_device_info(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_snap_prvs_devi_t *device_info,
                         uint16_t buf_sz,
                         uint32_t wait_ms);

/** Sign data
 *
 * Sends generated device information for the device. Device signs it and returns signature back.
 *
 * \param[in] netif SNAP service descriptor. If NULL, default one will be used.
 * \param[in] mac Device MAC address.
 * \param[in] data Data to be signed. Must not be NULL.
 * \param[in] data_sz \a data size. Must not be zero.
 * \param[out] signature Output buffer for signature. Must not be NULL.
 * \param[in] buf_sz \a signature buffer size. Must not be zero.
 * \param[out] signature_sz Buffer to store \a signature size. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_prvs_sign_data(const vs_netif_t *netif,
                       const vs_mac_addr_t *mac,
                       const uint8_t *data,
                       uint16_t data_sz,
                       uint8_t *signature,
                       uint16_t buf_sz,
                       uint16_t *signature_sz,
                       uint32_t wait_ms);

/** Set data
 *
 * Sends request for set \a element provision data for \a mac device.
 *
 * #vs_snap_prvs_set and #vs_snap_prvs_get calls are used for prepare device provision.
 *
 * \param[in] netif SNAP service descriptor. If NULL, default one will be used.
 * \param[in] mac Device MAC address.
 * \param[in] element Element identificator.
 * \param[in] data Data to be saved. Must not be NULL.
 * \param[in] data_sz \a data size. Must not be zero.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_prvs_set(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_snap_prvs_element_e element,
                 const uint8_t *data,
                 uint16_t data_sz,
                 uint32_t wait_ms);

/** Get data
 *
 * Sends request for get \a element provision data from \a mac device
 *
 * #vs_snap_prvs_set and #vs_snap_prvs_get calls are used for prepare device provision.
 *
 * \param[in] netif SNAP service descriptor. If NULL, default one will be used.
 * \param[in] mac Device MAC address.
 * \param[in] element Element identifier.
 * \param[out] data Output buffer for data. Must not be NULL.
 * \param[in] buf_sz \a signature buffer size. Must not be zero.
 * \param[out] data_sz Buffer to store \a data size. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_prvs_get(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_snap_prvs_element_e element,
                 uint8_t *data,
                 uint16_t buf_sz,
                 uint16_t *data_sz,
                 uint32_t wait_ms);

/** Set Trust List header
 *
 * Sends request for set \a data to the Trust List header for \a mac device
 *
 * \param[in] netif SNAP service descriptor. If NULL, default one will be used.
 * \param[in] mac Device MAC address.
 * \param[in] element Element identificator.
 * \param[in] data Data to be saved. Must not be NULL.
 * \param[in] data_sz \a data size. Must not be zero.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_prvs_set_tl_header(const vs_netif_t *netif,
                           const vs_mac_addr_t *mac,
                           const uint8_t *data,
                           uint16_t data_sz,
                           uint32_t wait_ms);


/** Set Trust List footer
 *
 * Sends request for set \a data to the Trust List footer for \a mac device
 *
 * \param[in] netif SNAP service descriptor. If NULL, default one will be used.
 * \param[in] mac Device MAC address.
 * \param[in] data Data to be saved. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_snap_prvs_set_tl_footer(const vs_netif_t *netif,
                           const vs_mac_addr_t *mac,
                           const uint8_t *data,
                           uint16_t data_sz,
                           uint32_t wait_ms);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // PRVS_CLIENT

#endif // VS_SECURITY_SDK_SNAP_SERVICES_PRVS_CLIENT_H
