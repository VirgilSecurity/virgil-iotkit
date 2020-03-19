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

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_MSGR_SERVER_H
#define VS_SECURITY_SDK_SNAP_SERVICES_MSGR_SERVER_H

#if MSGR_SERVER

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/msgr/msgr-structs.h>
#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Get data from a device
 *
 * This function is called by receiving request to get actual data from a remote device or every periodical poll
 * processing.
 *
 * \param[out] data Output buffer to store data. Must not be NULL.
 * \param[in] buf_sz Buffer size. Must not be zero.
 * \param[out] data_sz Pointer to save stored data size. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_msgr_get_data_cb_t)(uint8_t *data, uint32_t buf_sz, uint32_t *data_sz);

/** Set data to a device
 *
 * This function is called by receiving request to set data to a remote device.
 *
 * \param[out] data Data to be saved. Must not be NULL.
 * \param[out] data_sz Data size. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_msgr_set_data_cb_t)(uint8_t *data, uint32_t data_sz);

/** MSGR server implementations
 *
 * \note Any callback can be NULL. In this case, there will be no actions with requests.
 *
 */
typedef struct {
    vs_snap_msgr_get_data_cb_t get_data; /**< Get data to send it over snap */
    vs_snap_msgr_set_data_cb_t set_data; /**< Set data received from snap*/
} vs_snap_msgr_server_service_t;

/** MSGR Server SNAP Service implementation
 *
 * This call returns MSGR server implementation. It must be called before any MSGR call.
 *
 * \param[in] impl Snap MSGR Server functions implementation.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
const vs_snap_service_t *
vs_snap_msgr_server(vs_snap_msgr_server_service_t impl);

vs_status_e
vs_snap_msgr_start_notification(const vs_netif_t *netif);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // MSGR_SERVER

#endif // VS_SECURITY_SDK_SNAP_SERVICES_MSGR_SERVER_H
