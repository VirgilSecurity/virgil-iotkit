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

/*! \file prvs-client.h
 * \brief PRVS for client
 */

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_PRVS_CLIENT_H
#define VS_SECURITY_SDK_SDMP_SERVICES_PRVS_CLIENT_H

#if PRVS_CLIENT

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/sdmp-structs.h>

#include <virgil/iot/protocols/sdmp/prvs/prvs-structs.h>
#include <virgil/iot/provision/provision-structs.h>

// TODO : description???
/** Wait and stop callback
 *
 * \a stop_wait_func member or \ref vs_sdmp_prvs_client_impl_t structure.
 * \a wait_func member or \ref vs_sdmp_prvs_client_impl_t structure.
 *
 * \param[in] condition
 * \param[in] expect
 *
 * \return \ref vs_status_e \ref VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_sdmp_prvs_stop_wait_t)(int *condition, int expect);

// TODO : description???
/** Wait callback
 *
 * \param[in] wait_ms
 * \param[in] condition
 * \param[in] idle
 *
 * \return \ref vs_status_e \ref VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_sdmp_prvs_wait_t)(uint32_t wait_ms, int *condition, int idle);

// TODO : members description???
/** PRVS client implementation
 */
typedef struct {
    vs_sdmp_prvs_stop_wait_t stop_wait_func;
    vs_sdmp_prvs_wait_t wait_func;
} vs_sdmp_prvs_client_impl_t;

/** PRVS Client SDMP Service implementation
 *
 * This call returns PRVS client implementation. It must be called before any PRVS call.
 *
 * \param[in] impl \ref vs_sdmp_prvs_client_impl_t callback functions. Must not be NULL.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
const vs_sdmp_service_t *
vs_sdmp_prvs_client(vs_sdmp_prvs_client_impl_t impl);

/** Enumerate devices
 *
 * Sends request for all devices that have not been initialized.
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[out] list \ref vs_sdmp_prvs_dnid_list_t Buffer with devices list. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_prvs_enum_devices(const vs_netif_t *netif, vs_sdmp_prvs_dnid_list_t *list, uint32_t wait_ms);

// TODO : check description
// TODO : asav_res ?
/** Save provision
 *
 * Sends request to save provision
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[in] mac \ref vs_mac_addr_t Device MAC address.
 * \param[out] asav_res
 * \param[in] buf_sz Buffer size
 * \param[in] wait_ms Time to wait response.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_prvs_save_provision(const vs_netif_t *netif,
                            const vs_mac_addr_t *mac,
                            uint8_t *asav_res,
                            uint16_t buf_sz,
                            uint32_t wait_ms);

/** Request device information
 *
 * Sends request for \a mac device information
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[in] mac \ref vs_mac_addr_t Device MAC address.
 * \param[out] device_info \ref vs_sdmp_prvs_devi_t Device information output buffer. Must not be NULL.
 * \param[in] buf_sz Buffer size
 * \param[in] wait_ms Time to wait response.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_prvs_device_info(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_sdmp_prvs_devi_t *device_info,
                         uint16_t buf_sz,
                         uint32_t wait_ms);

// TODO : check description
/** Sign data
 *
 * Sends request for \a mac device information
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[in] mac \ref vs_mac_addr_t Device MAC address.
 * \param[in] data Data to be signed. Must not be NULL.
 * \param[in] data_sz \a data size. Must not be zero.
 * \param[out] signature Output buffer for signature. Must not be NULL.
 * \param[in] buf_sz \a signature buffer size. Must not be zero.
 * \param[out] signature_sz Buffer to store \a signature size. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_prvs_sign_data(const vs_netif_t *netif,
                       const vs_mac_addr_t *mac,
                       const uint8_t *data,
                       uint16_t data_sz,
                       uint8_t *signature,
                       uint16_t buf_sz,
                       uint16_t *signature_sz,
                       uint32_t wait_ms);

// TODO : check description
/** Set data
 *
 * Sends request for set \a element provision data for \a mac device
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[in] mac \ref vs_mac_addr_t Device MAC address.
 * \param[in] element \ref vs_sdmp_prvs_element_e element.
 * \param[in] data Data to be saved. Must not be NULL.
 * \param[in] data_sz \a data size. Must not be zero.
 * \param[in] wait_ms Time to wait response.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_prvs_set(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_sdmp_prvs_element_e element,
                 const uint8_t *data,
                 uint16_t data_sz,
                 uint32_t wait_ms);


// TODO : check description
/** Get data
 *
 * Sends request for get \a element provision data from \a mac device
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[in] mac \ref vs_mac_addr_t Device MAC address.
 * \param[in] element \ref vs_sdmp_prvs_element_e element.
 * \param[out] data Output buffer for data. Must not be NULL.
 * \param[in] buf_sz \a signature buffer size. Must not be zero.
 * \param[out] data_sz Buffer to store \a data size. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_prvs_get(const vs_netif_t *netif,
                 const vs_mac_addr_t *mac,
                 vs_sdmp_prvs_element_e element,
                 uint8_t *data,
                 uint16_t buf_sz,
                 uint16_t *data_sz,
                 uint32_t wait_ms);

// TODO : check description
/** Set Trust List header
 *
 * Sends request for set \a data to Trust List header for \a mac device
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[in] mac \ref vs_mac_addr_t Device MAC address.
 * \param[in] element \ref vs_sdmp_prvs_element_e element.
 * \param[in] data Data to be saved. Must not be NULL.
 * \param[in] data_sz \a data size. Must not be zero.
 * \param[in] wait_ms Time to wait response.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_prvs_set_tl_header(const vs_netif_t *netif,
                           const vs_mac_addr_t *mac,
                           const uint8_t *data,
                           uint16_t data_sz,
                           uint32_t wait_ms);


// TODO : check description
/** Set Trust List footer
 *
 * Sends request for set \a data to Trust List footer for \a mac device
 *
 * \param[in] netif \ref vs_netif_t SDMP service descriptor. Must not be NULL.
 * \param[in] mac \ref vs_mac_addr_t Device MAC address.
 * \param[in] data Data to be saved. Must not be NULL.
 * \param[in] wait_ms Time to wait response.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
vs_status_e
vs_sdmp_prvs_set_tl_footer(const vs_netif_t *netif,
                           const vs_mac_addr_t *mac,
                           const uint8_t *data,
                           uint16_t data_sz,
                           uint32_t wait_ms);

#ifdef __cplusplus
}
#endif

#endif // PRVS_CLIENT

#endif // VS_SECURITY_SDK_SDMP_SERVICES_PRVS_CLIENT_H
