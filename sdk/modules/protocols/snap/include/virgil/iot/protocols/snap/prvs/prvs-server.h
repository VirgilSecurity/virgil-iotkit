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

/*! \file prvs-server.h
 * \brief PRVS for server
 *
 * PRVS is the provision service. PRVS Server is a device, PRVS Client is the factory server with factory initializer
 utility.
 * Client prepares device's card, server signs it, and client saves this information.
 *
 * \section prvs_server_usage PRVS Server usage
 *
 * For server it is enough to prepare security module and pass it to the #vs_snap_prvs_server initializer :
 *
 * \code
 *
 *     vs_secmodule_impl_t *secmodule_impl;         // Security module implementation
 *     vs_storage_op_ctx_t slots_storage_impl;      // Slots storage implementation
 *     const vs_snap_service_t *snap_prvs_server;   // PRVS Server

 *     // Initialize slots_storage_impl, secmodule_impl.
 *
 *     // You can use software implementation :
 *     secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);
 *
 *     snap_prvs_server = vs_snap_prvs_server(secmodule_impl);
 *    STATUS_CHECK(vs_snap_register_service(snap_prvs_server), "Cannot register PRVS service");
 *
 * \endcode
 *
 * Virgil IoT KIT manages PRVS Server service automatically by using Provision module.
 */

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_PRVS_SERVER_H
#define VS_SECURITY_SDK_SNAP_SERVICES_PRVS_SERVER_H

#if PRVS_SERVER

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/prvs/prvs-structs.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/secmodule/secmodule.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** PRVS Server SNAP Service implementation
 *
 * This call returns PRVS Server implementation. It must be called before any PRVS call.
 *
 * \param[in] impl Callback functions. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
const vs_snap_service_t *
vs_snap_prvs_server(vs_secmodule_impl_t *secmodule);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // PRVS_SERVER

#endif // VS_SECURITY_SDK_SNAP_SERVICES_PRVS_SERVER_H
