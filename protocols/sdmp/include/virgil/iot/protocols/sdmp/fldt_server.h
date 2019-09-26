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

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_FLDT_SERVER_H
#define VS_SECURITY_SDK_SDMP_SERVICES_FLDT_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/update/update.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/status_code/status_code.h>

//
//  Callbacks
//

// . "Add file type"
// .  Add file type asked by client
typedef vs_status_code_e (*vs_fldt_server_add_filetype)(const vs_update_file_type_t *file_type,
                                                        vs_update_interface_t **update_ctx);

const vs_sdmp_service_t *
vs_sdmp_fldt_server(void);

//
//  Customer API
//

vs_status_code_e
vs_fldt_init_server(const vs_mac_addr_t *gateway_mac, vs_fldt_server_add_filetype add_filetype);

vs_status_code_e
vs_fldt_update_server_file_type(const vs_update_file_type_t *file_type,
                                vs_update_interface_t *update_context,
                                bool broadcast_file_info);

void
vs_fldt_destroy_server(void);

#ifdef __cplusplus
}
#endif

#endif // VS_SECURITY_SDK_SDMP_SERVICES_FLDT_SERVER_H
