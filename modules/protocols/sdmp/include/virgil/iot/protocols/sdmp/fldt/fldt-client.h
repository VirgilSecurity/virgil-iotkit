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

/*! \file fldt-client.h
 * \brief FLDT for client
 *
 * FLDT protocol is used to download new file version from gateway to client. This module is used to process client part
 * of FLDT protocol.
 *
 * \section fldt_client_usage FLDT Client Usage
 *
 * Client side downloads new file versions and checks them. \ref vs_fldt_got_file function is called after file upgrading.
 * In most case it used to output new file version information and gateway address.
 * To successfully file downloading process \ref vs_update_interface_t must be provided for each file type. You can see
 * function \ref vs_firmware_update_file_type for Firmware example and \ref vs_tl_update_file_type for Trust List one.
 *
 * Here you can see an example of FLDT client initialization :
 * \code
 *  const vs_sdmp_service_t *sdmp_fldt_client;
 *  sdmp_fldt_client = vs_sdmp_fldt_client( _on_file_updated );
 *  STATUS_CHECK( vs_sdmp_register_service( sdmp_fldt_client ), "Cannot register FLDT client service");
 *  STATUS_CHECK( vs_fldt_client_add_file_type( vs_firmware_update_file_type(), vs_firmware_update_ctx() ), "Unable to add Firmware file type" );
 *  STATUS_CHECK( vs_fldt_client_add_file_type( vs_tl_update_file_type(), vs_tl_update_ctx() ), "Unable to add Trust List file type" );
 * \endcode
 *
 * You can see minimalistic \ref vs_fldt_got_file function example below :
 * \code
 * void _on_file_updated(vs_update_file_type_t *file_type,
 *                  const vs_file_version_t *prev_file_ver,
 *                  const vs_file_version_t *new_file_ver,
 *                  vs_update_interface_t *update_interface,
 *                  const vs_mac_addr_t *gateway,
 *                  bool successfully_updated) {
 *     (void) prev_file_ver;
 *     (void) new_file_ver;
 *     (void) update_interface;
 *     (void) gateway;
 *
 *     switch(file_type->type) {
 *     case VS_UPDATE_FIRMWARE :   VS_LOG_INFO( "New Firmware has been loaded" );   break;
 *     case VS_UPDATE_TRUST_LIST : VS_LOG_INFO( "New Trust List has been loaded" ); break;
 *     }
 *
 *     if (file_type->type == VS_UPDATE_FIRMWARE && successfully_updated) {
 *         _app_restart();
 *     }
 * }
 * \endcode
 *
 * In this example _app_restart() function is called for firmware that has been successfully updated.
 */

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H
#define VS_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H

#if FLDT_CLIENT

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/sdmp-structs.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/update/update.h>

/** Got new file callback
 *
 * Callback for \ref vs_sdmp_fldt_client function.
 * This callback is used when new file has been fully loaded. See \ref fldt_client_usage for details.
 *
 * \param[in] file_type File type descriptor. Cannot be NULL.
 * \param[in] prev_file_ver Current file version before loading new one. Cannot be NULL.
 * \param[in] new_file_ver Has been loaded file version. Cannot be NULL.
 * \param[in] update_interface Update interface for current file type. Cannot be NULL.
 * \param[in] gateway Gateway's MAC address. Cannot be NULL.
 * \param[in] successfully_updated True if file has been successfully updated.
 *
 */
typedef void (*vs_fldt_got_file)(vs_update_file_type_t *file_type,
                                 const vs_file_version_t *prev_file_ver,
                                 const vs_file_version_t *new_file_ver,
                                 vs_update_interface_t *update_interface,
                                 const vs_mac_addr_t *gateway,
                                 bool successfully_updated);

/** FLDT Client SDMP Service implementation
 *
 * This call returns FLDT client implementation. It must be called before any FLDT call.
 *
 * \param[in] got_file_callback Callback. Must not be NULL.
 *
 * \return \ref vs_sdmp_service_t SDMP service description. Use this pointer to call \ref vs_sdmp_register_service.
 */
const vs_sdmp_service_t *
vs_sdmp_fldt_client(vs_fldt_got_file got_file_callback);

/** Add file type
 *
 * FLDT client has the list of file types that it processes. This call adds new file type or update previously added one.
 *
 * \param[in] file_type File type to be added. Must not be NULL.
 * \param[in] update_ctx Update context for current file type. Must not be NULL.
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_fldt_client_add_file_type(const vs_update_file_type_t *file_type, vs_update_interface_t *update_ctx);

#ifdef __cplusplus
}
#endif

#endif // FLDT_CLIENT

#endif // VS_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H
