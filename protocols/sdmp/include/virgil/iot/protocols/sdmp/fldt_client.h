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

#ifndef VS_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H
#define VS_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/update/update.h>

//
//  Callbacks
//

// . File has been downloaded
// . file_type - file type
// . prev_file_ver - previous file version and its type
// . new_file_ver - sent file version and its type
// . gateway - gateway that has sent this file
// . successfully_updated - true while file vas updated else false

typedef void (*vs_fldt_got_file)(vs_update_file_type_t *file_type,
                                 const vs_update_file_version_t *prev_file_ver,
                                 const vs_update_file_version_t *new_file_ver,
                                 const vs_mac_addr_t *gateway,
                                 bool successfully_updated);

const vs_sdmp_service_t *
vs_sdmp_fldt_client(void);

//
//  Customer API
//

vs_status_code_e
vs_fldt_init_client(vs_fldt_got_file got_file_callback);

vs_status_code_e
vs_fldt_update_client_file_type(const vs_update_file_type_t *file_type, vs_update_interface_t *update_ctx);

void
vs_fldt_destroy_client(void);

#ifdef __cplusplus
}
#endif

#endif // VS_SECURITY_SDK_SDMP_SERVICES_FLDT_CLIENT_H
