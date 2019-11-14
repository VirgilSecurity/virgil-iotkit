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

/**
 * @file vs-softhsm.h
 * @brief Software crypto implementation
 *
 * This library can be used when no Hardware Security Module support provided.
 *
 * \section vs-softhsm-usage Virgil Security Software Security Module Usage
 *
 * You need initialize vs-softhsm module before its usage and free it after. See code below for example :
 *
 *
 *
 */

#ifndef HELPERS_VS_SOFTHSM_H
#define HELPERS_VS_SOFTHSM_H

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/storage_hal/storage_hal.h>

#define VS_SLOTS_STORAGE_MAX_SIZE (1024)

/** Initialize software crypto implementation
 *
 * \param[in] slots_storage_impl Storage context. Must not be NULL.
 *
 * \return HSM implementation
 */
vs_hsm_impl_t *
vs_softhsm_impl(vs_storage_op_ctx_t *slots_storage_impl);

/** Destroy software crypto implementation
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_softhsm_deinit(void);

#endif // HELPERS_VS_SOFTHSM_H
