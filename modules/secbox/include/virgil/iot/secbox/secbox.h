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

/*! \file secbox.h
 * \brief Security Box implementation
 *
 */

#ifndef SECBOX_H
#define SECBOX_H

#include <stdint.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/secmodule/secmodule.h>

/** Security box operation type */
typedef enum {
    VS_SECBOX_SIGNED,               /**< Signed data */
    VS_SECBOX_SIGNED_AND_ENCRYPTED, /**< Signed and encrypted data */
} vs_secbox_type_t;

/** Initialize Security Box
 *
 * \param[in] ctx Storage context. Must not be NULL.
 * \param[in] secmodule HSM implementation. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secbox_init(vs_storage_op_ctx_t *ctx, vs_hsm_impl_t *secmodule);

/** Destroy Security Box
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secbox_deinit(void);

/** Security Box element size
 *
 * \param[in] id Element ID
 *
 * \return Element size or #vs_status_e negative value in case of error
 */
ssize_t
vs_secbox_file_size(vs_storage_element_id_t id);

/** Security Box element save
 *
 * \param[in] type Security operation type.
 * \param[in] id Element ID
 * \param[in] data Data buffer. Must not be NULL.
 * \param[in] data_sz Data size. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secbox_save(vs_secbox_type_t type, vs_storage_element_id_t id, const uint8_t *data, size_t data_sz);

/** Security Box element load
 *
 * \param[in] id Element ID
 * \param[out] data Data buffer. Must not be NULL.
 * \param[in] data_sz Data size. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secbox_load(vs_storage_element_id_t id, uint8_t *data, size_t data_sz);


/** Security Box element delete
 *
 * \param[in] id Element ID
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_secbox_del(vs_storage_element_id_t id);

#endif // SECBOX_H
