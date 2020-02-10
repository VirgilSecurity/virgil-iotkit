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

/*! \file fldt-server.h
 * \brief FLDT for server
 *
 * FLDT service is used to download new file version from gateway to client. This module is used to process server part
 * of FLDT protocol.
 *
 * \section fldt_server_usage FLDT Server Usage
 *
 * Server side sends new file versions provided by #vs_fldt_server_add_file_type call. Also it sends information about
 * present files by client requests. Files must be previously listed by #vs_fldt_server_add_file_type call. If requested
 * file has not been added, #vs_fldt_server_add_filetype callback is called to provide such information.
 * In most case it used to output new file version information and gateway address.
 * To successfully file broadcasting #vs_update_interface_t must be provided for each file type. You can see
 * function #vs_firmware_update_file_type for Firmware example and #vs_tl_update_file_type for Trust List one.
 *
 * Here you can see an example of FLDT server initialization :
 * \code
 *  const vs_snap_service_t *snap_fldt_server;
 *  const vs_mac_addr_t mac_addr;
 *  snap_fldt_server = vs_snap_fldt_server( &mac_addr, _add_filetype );
 *
 *  STATUS_CHECK( vs_snap_register_service(snap_fldt_server),
 *      "Cannot register FLDT server service" );
 *  STATUS_CHECK( vs_fldt_server_add_file_type( vs_firmware_update_file_type(), vs_firmware_update_ctx(), false ),
 *      "Unable to add Firmware file type" );
 *  STATUS_CHECK( vs_fldt_server_add_file_type( vs_tl_update_file_type(), vs_tl_update_ctx(), false ),
 *      "Unable to add Trust List file type" );
 *
 * * \endcode
 *
 * You can see #vs_fldt_server_add_filetype function example below :
 * \code
 * static vs_status_e
 * _add_filetype(const vs_update_file_type_t *file_type, vs_update_interface_t **update_ctx) {
 *     switch (file_type->type) {
 *     case VS_UPDATE_FIRMWARE:
 *         *update_ctx = vs_firmware_update_ctx();
 *         break;
 *     case VS_UPDATE_TRUST_LIST:
 *         *update_ctx = vs_tl_update_ctx();
 *         break;
 *     default:
 *         VS_LOG_ERROR("Unsupported file type : %d", file_type->type);
 *         return VS_CODE_ERR_UNSUPPORTED_PARAMETER;
 *     }
 *
 *     return VS_CODE_OK;
 * }
 * \endcode
 *
 */

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_FLDT_SERVER_H
#define VS_SECURITY_SDK_SNAP_SERVICES_FLDT_SERVER_H

#if FLDT_SERVER

#include <virgil/iot/update/update.h>
#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/status_code/status_code.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Add new file type callback
 *
 * Callback for #vs_snap_fldt_server function.
 * This callback is used when gateway receives request for file type that has not been added by
 * #vs_fldt_server_add_file_type call.
 *
 * \warning Valid pointer to the update context with all implementations must be provided.
 *
 * \note In next release default implementation for Firmware and Trust List will be provided.
 *
 * \param[in] file_type File type descriptor. Cannot be NULL.
 * \param[in, out] update_ctx Pointer to store update nont NULL context pointer for new file type. Cannot be NULL.
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_fldt_server_add_filetype_cb)(const vs_update_file_type_t *file_type,
                                                      vs_update_interface_t **update_ctx);

/** FLDT Server SNAP Service implementation
 *
 * This call returns FLDT server implementation. It must be called before any FLDT call.
 *
 * \param[in] gateway_mac Gateway's MAC address. Must not be NULL.
 * \param[in] add_filetype Callback. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
const vs_snap_service_t *
vs_snap_fldt_server(const vs_mac_addr_t *gateway_mac, vs_fldt_server_add_filetype_cb add_filetype);

/** Add file type
 *
 * FLDT server has the list of file types that it processes. This call adds new file type or update previously added
 * one.
 *
 * \param[in] file_type File type to be added. Must not be NULL.
 * \param[in] update_ctx Update context for current file type. Must not be NULL.
 * \param[in] broadcast_file_info true if gateways has to broadcast information about file provided.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_fldt_server_add_file_type(const vs_update_file_type_t *file_type,
                             vs_update_interface_t *update_context,
                             bool broadcast_file_info);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // FLDT_SERVER

#endif // VS_SECURITY_SDK_SNAP_SERVICES_FLDT_SERVER_H
