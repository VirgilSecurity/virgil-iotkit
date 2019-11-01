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

/*! \file prvs-server.h
 * \brief PRVS for server
 */
// TODO : examples!

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_PRVS_SERVER_H
#define VS_SECURITY_SDK_SDMP_SERVICES_PRVS_SERVER_H

#if PRVS_SERVER

#ifdef __cplusplus
extern "C" {
#endif
#include <virgil/iot/protocols/sdmp/sdmp-structs.h>
#include <virgil/iot/protocols/sdmp/prvs/prvs-structs.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/hsm/hsm.h>

/** PRVS Server SDMP Service implementation
 *
 * This call returns PRVS server implementation. It must be called before any PRVS call.
 *
 * \param[in] impl Callback functions. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
const vs_sdmp_service_t *
vs_sdmp_prvs_server(vs_hsm_impl_t *hsm);

#ifdef __cplusplus
}
#endif

#endif // PRVS_SERVER

#endif // VS_SECURITY_SDK_SDMP_SERVICES_PRVS_SERVER_H
