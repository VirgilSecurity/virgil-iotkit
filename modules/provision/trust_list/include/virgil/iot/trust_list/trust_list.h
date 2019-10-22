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

/*! \file trust_list.h
 * \brief Trust List
 */

#ifndef TRUST_LIST_H
#define TRUST_LIST_H

#include <stdint.h>
#include <stdbool.h>
#include <virgil/iot/hsm/hsm.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/trust_list/tl_structs.h>

/** Trust List element type
 *
 * Used for save Trust List header, data or footer by \ref vs_tl_save_part call or load by \ref vs_tl_load_part call
 */
typedef enum {
    VS_TL_ELEMENT_MIN = 0,
    VS_TL_ELEMENT_TLH, /**< Trust List header */
    VS_TL_ELEMENT_TLC, /**< Trust List data chunk */
    VS_TL_ELEMENT_TLF, /**< Trust List footer */
    VS_TL_ELEMENT_MAX,
} vs_tl_element_e;

/** Trust List element description */
typedef struct vs_tl_element_info_s {
    vs_tl_element_e id; /**< Trust List header, data chunk or footer selection */
    size_t index; /**< Trust List data chunk number */
} vs_tl_element_info_t;

/** Trust List initialization
 *
 * \param[in] op_ctx \ref vs_storage_op_ctx_t storage context. Must not be NULL.
 * \param[in] hsm \ref vs_hsm_impl_t HSM implementation. Must not be NULL.
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_tl_init(vs_storage_op_ctx_t *op_ctx, vs_hsm_impl_t *hsm);

/** Trust List destruction
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_tl_deinit();

/** Trust List element saving
 *
 * \param[in] element_info \ref vs_tl_element_info_t element selection. Must not be NULL.
 * \param[in] in_data Data to be saved. Must not be NULL.
 * \param[in] data_sz Data size. Must not be zero.
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_tl_save_part(vs_tl_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz);

/** Trust List element loading
 *
 * \param[in] element_info \ref vs_tl_element_info_t element selection. Must not be NULL.
 * \param[out] out_data Output buffer to store data. Must not be NULL.
 * \param[in] buf_sz Buffer size. Must not be zero.
 * \param[out] out_sz Pointer to save stored data size. Must not be NULL.
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_tl_load_part(vs_tl_element_info_t *element_info, uint8_t *out_data, uint16_t buf_sz, uint16_t *out_sz);

/** Update interface for Trust List
 *
 * \return \ref vs_update_interface_t
 */
vs_update_interface_t *
vs_tl_update_ctx(void);

/** Trust List file type
 *
 * \return \ref vs_update_file_type_t
 */
const vs_update_file_type_t *
vs_tl_update_file_type(void);

/** Convert Trust List header to host
 *
 * \param[in] src_data \ref vs_tl_header_t Data source. Must not be NULL.
 * \param[out] dst_data \ref vs_tl_header_t Data destination. Must not be NULL.
 */
void
vs_tl_header_to_host(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data);

#endif // TRUST_LIST_H
