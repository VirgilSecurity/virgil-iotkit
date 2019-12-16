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

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>

#include <virgil/iot/vs-ateccx08A-secmodule/vs-ateccx08A-secmodule.h>
#include <private/vs-ateccx08A-secmodule-internal.h>

/******************************************************************************/
void
vs_secmodule_atecc08A_sha256_init(vs_secmodule_sw_sha256_ctx *ctx) {
}

/******************************************************************************/
vs_status_e
vs_secmodule_atecc08A_sha256_update(vs_secmodule_sw_sha256_ctx *ctx, const uint8_t *message, uint32_t len) {

    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
vs_status_e
vs_secmodule_atecc08A_sha256_final(vs_secmodule_sw_sha256_ctx *ctx, uint8_t *digest) {

    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/

vs_status_e
_fill_soft_hash_impl(vs_secmodule_impl_t *secmodule_impl) {
    CHECK_NOT_ZERO_RET(secmodule_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);

    secmodule_impl->hash_init = vs_secmodule_atecc08A_sha256_init;
    secmodule_impl->hash_update = vs_secmodule_atecc08A_sha256_update;
    secmodule_impl->hash_finish = vs_secmodule_atecc08A_sha256_final;

    return VS_CODE_OK;
}
