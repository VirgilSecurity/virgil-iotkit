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

/*! \file trust_list.h
 * \brief Trust List module
 *
 * This file provides interface for Trust Lists processing.
 *
 * Trust List contains the list of trusted public keys and signatures. Initial Trust List is obtained by device during
 * provision. After that, it can be upgraded by Update library using FLDT service.
 *
 * \section trust_list_usage Trust List Usage
 *
 * Trust List is maintained by Virgil IoT KIT modules and doesn't need to be processed by user. Nonetheless, there
 * are some places where it needs user's attention :
 *
 * - Gateway needs to initialize Trust List file type to retransmit it by Update library and to provide
 * #vs_fldt_server_add_filetype_cb for FLDT Server service :
 *
 * \code
 *
 * vs_status_e
 * _add_filetype(const vs_update_file_type_t *file_type, vs_update_interface_t **update_ctx) {
 *     switch (file_type->type) {
 *
 *     // ...
 *
 *     // Trust List file type
 *         case VS_UPDATE_TRUST_LIST:
 *             *update_ctx = vs_tl_update_ctx();
 *             break;
 *     }
 *
 *     return VS_CODE_OK;
 * }
 *
 * // ...
 *
 *     const vs_snap_service_t *snap_fldt_server;   // FLDT Server service
 *     vs_mac_addr_t mac_addr;                      // Own MAC address
 *
 *     // Initialize mac_addr
 *
 *     //  FLDT server service
 *     snap_fldt_server = vs_snap_fldt_server(&mac_addr, _add_filetype);
 *     STATUS_CHECK(vs_snap_register_service(snap_fldt_server), "Cannot register FLDT server service");
 *     STATUS_CHECK(vs_fldt_server_add_file_type(vs_tl_update_file_type(), vs_tl_update_ctx(), false),
 *                  "Unable to add Trust List file type");
 *     // Other file types
 *
 * \endcode
 *
 * - After the Gateway receives the new Trust List using Cloud library, it is necessary to send the Trust List version
 * to Things. Use #vs_tl_load_part fir this purpose. This method reads Trust List header :
 *
 * \code
 *
 *  vs_tl_element_info_t elem = {.id = VS_TL_ELEMENT_TLH};      // Trust List header to be read
 *  vs_tl_header_t tl_header;                                   // Header
 *  uint16_t tl_header_sz = sizeof(tl_header);                  // Header size
 *  vs_update_file_type_t tl_info;                              // Trust List file update information
 *
 *  // Load latest local Trust List
 *  STATUS_CHECK(vs_tl_load_part(&elem, (uint8_t *)&tl_header, tl_header_sz, &tl_header_sz) &&
 *       tl_header_sz == sizeof(tl_header), "Unable to load Trust List header");
 *  vs_tl_header_to_host(&tl_header, &tl_header);
 *
 *  // Prepare Update information
 *  memset(tl_info, 0, sizeof(vs_update_file_type_t));
 *  memcpy(&tl_info.info.version, &tl_header.version, sizeof(vs_file_version_t));
 *
 *  tl_info.type = VS_UPDATE_TRUST_LIST;
 *
 *  // Broadcast new Trust List information
 *  STATUS_CHECK(vs_fldt_server_add_file_type(&tl_info, vs_tl_update_ctx(), true),
 *          "Unable to add new Trust List");
 *
 * \endcode
 */

#ifndef TRUST_LIST_H
#define TRUST_LIST_H

#include <stdint.h>
#include <stdbool.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/trust_list/tl_structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Trust List initialization
 *
 * Initializes Trust List.
 *
 * \note It is called by #vs_provision_init.
 *
 * \param[in] op_ctx Storage context. Must not be NULL.
 * \param[in] secmodule Security Module implementation. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_tl_init(vs_storage_op_ctx_t *op_ctx, vs_secmodule_impl_t *secmodule, vs_file_ver_info_cb_t ver_info_cb);

/** Trust List destruction
 *
 * Destroys Trust List.
 *
 * \note It is called by #vs_provision_deinit.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_tl_deinit(void);

/** Trust List element saving
 *
 * Saves Trust List header, footer or data chunk. Element selection is performed by \a element_info selector.
 *
 * \param[in] element_info Element selection. Must not be NULL.
 * \param[in] in_data Data to be saved. Must not be NULL.
 * \param[in] data_sz Data size. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_tl_save_part(vs_tl_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz);

/** Trust List element loading
 *
 * Loads Trust List header, footer or data chunk. Element selection is performed by \a element_info selector.
 *
 * \param[in] element_info Element selection. Must not be NULL.
 * \param[out] out_data Output buffer to store data. Must not be NULL.
 * \param[in] buf_sz Buffer size. Must not be zero.
 * \param[out] out_sz Pointer to save stored data size. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_tl_load_part(vs_tl_element_info_t *element_info, uint8_t *out_data, uint16_t buf_sz, uint16_t *out_sz);

/** Update interface for Trust List
 *
 * Returns Update context for Trust List.
 *
 * \return #vs_update_interface_t
 */
vs_update_interface_t *
vs_tl_update_ctx(void);

/** Trust List file type
 *
 * Returns Trust List file type for Update module.
 *
 * \return #vs_update_file_type_t
 */
const vs_update_file_type_t *
vs_tl_update_file_type(void);

/** Convert Trust List header to host
 *
 * Convert Trust List header to the host format.
 *
 * \param[in] src_data Data source. Must not be NULL.
 * \param[out] dst_data Data destination. Must not be NULL.
 */
void
vs_tl_header_to_host(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data);

/** Convert Trust List header to network
 *
 * Convert Trust List header to the network format.
 *
 * \param[in] src_data Data source. Must not be NULL.
 * \param[out] dst_data Data destination. Must not be NULL.
 */
void
vs_tl_header_to_net(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // TRUST_LIST_H
