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

/*! \file provision.h
 * \brief Provision interface implementation
 */

#ifndef VS_IOT_PROVISION_H
#define VS_IOT_PROVISION_H

#include <virgil/iot/hsm/hsm.h>
#include <virgil/iot/provision/provision-structs.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/storage_hal/storage_hal.h>

/** File version */
typedef struct __attribute__((__packed__)) {
    uint8_t dummy[4];
    uint8_t major; /**< Major version */
    uint8_t minor; /**< Minor version */
    uint8_t patch; /**< Patch version */
    uint8_t dev_milestone; /**< Device milestone */
    uint8_t dev_build; /**< Build number */
    uint32_t timestamp; /**< The number of seconds elapsed since January 1, 2015 UTC */
} vs_file_version_t;

/** File information */
typedef struct __attribute__((__packed__)) {
    vs_device_manufacture_id_t manufacture_id; /**< Manufacture ID */
    vs_device_type_t device_type; /**< Device type */
    vs_file_version_t version; /**< Version */
} vs_file_info_t;

/** Provision initialization
 *
 * \param[in] tl_storage_ctx Storage context. Must not be NULL.
 * \param[in] hsm HSM implementation. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_init(vs_storage_op_ctx_t *tl_storage_ctx, vs_hsm_impl_t *hsm);

/** Provision destruction
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_deinit(void);

/** Get slot number
 *
 * \param[in] id Storage context. Must not be NULL.
 * \param[in] hsm HSM implementation. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_get_slot_num(vs_provision_element_id_e id, uint16_t *slot);

/** Search high level public key
 *
 * \param[in] key_type Key type.
 * \param[in] ec_type Elliptic curve type.
 * \param[out] key Output buffer to save key. Must not be NULL.
 * \param[in] key_sz Key size. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_search_hl_pubkey(vs_key_type_e key_type, vs_hsm_keypair_type_e ec_type, uint8_t *key, uint16_t key_sz);

/** Verify high level public key
 *
 * \param[in] key_to_check Key to check. Must not be NULL.
 * \param[in] key_size Key size. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_verify_hl_key(const uint8_t *key_to_check, uint16_t key_size);

#endif // VS_IOT_PROVISION_H