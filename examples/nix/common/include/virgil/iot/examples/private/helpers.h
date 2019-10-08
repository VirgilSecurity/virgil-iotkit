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

#ifndef VS_CRYPTO_CONVERTERS_MACROS_H
#define VS_CRYPTO_CONVERTERS_MACROS_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>

#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/logger/logger.h>

#define MAX_KEY_SZ (128)

#define CHECK_BOOL(OPERATION, DESCRIPTION, ...)                                                                        \
    do {                                                                                                               \
        if (!(OPERATION)) {                                                                                            \
            VS_LOG_ERROR((DESCRIPTION), ##__VA_ARGS__);                                                                \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

#define CHECK_MEM_ALLOC(OPERATION, DESCRIPTION, ...) CHECK_BOOL(OPERATION, DESCRIPTION, ##__VA_ARGS__)

#define CHECK_VSCF(OPERATION, DESCRIPTION, ...)                                                                        \
    CHECK_BOOL((vscf_status_SUCCESS == (OPERATION)), DESCRIPTION, ##__VA_ARGS__)

#define NOT_ZERO(ARG)                                                                                                  \
    do {                                                                                                               \
        if (!(ARG)) {                                                                                                  \
            VS_LOG_ERROR("Argument " #ARG " must not be zero");                                                        \
            return VS_HSM_ERR_INVAL;                                                                                   \
        }                                                                                                              \
    } while (0)

const char *
get_slot_name(vs_iot_hsm_slot_e slot);

int
vs_hsm_keypair_get_prvkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type);


#endif // VS_CRYPTO_CONVERTERS_MACROS_H
