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

#ifndef VS_CLOUD_INCLUDE_H
#define VS_CLOUD_INCLUDE_H

#include <trust_list-config.h>
#include <stdlib-config.h>
#include <cloud-config.h>
#include <update-config.h>
#include <global-hal.h>
#include <endian-config.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <virgil/iot/firmware/firmware_hal.h>
#include <virgil/iot/hsm/asn1_cryptogram.h>
#include <virgil/iot/hsm/hsm_virgil_ecies.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/json/json_parser.h>

#include <virgil/iot/cloud/cloud.h>
#include <virgil/iot/cloud/private/cloud_hal.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/cloud/private/cloud_parse_manifest.h>
#include <virgil/iot/cloud/private/cloud_operations.h>
#include <virgil/iot/cloud/base64/base64.h>

#endif // VS_CLOUD_INCLUDE_H
