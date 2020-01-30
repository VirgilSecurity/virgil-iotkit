//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
 * \brief Provision interface
 *
 * Provision interface allows user to :
 * - Enumerate Trust List keys (#vs_provision_tl_find_first_key, #vs_provision_tl_find_next_key).
 * - Search for specified high level key in internal storage (#vs_provision_verify_hl_key).
 * - Verify high level public key (#vs_provision_verify_hl_key).
 * - Get slot number for specific element (#vs_provision_get_slot_num).
 * - Get Thing service URL (#vs_provision_cloud_url)
 *
 * \section provision_usage Provision Usage
 *
 * Provision library must be initialized before the first call and destroyed after the last one :
 *
 * \code
vs_status_e ret_code;                   // Result code
vs_storage_op_ctx_t tl_storage_impl;    // Trust List storage implementation
vs_secmodule_impl_t *secmodule_impl;    // Security Module implementation
vs_storage_op_ctx_t slots_storage_impl; // Slots storage implementation

// Initialize tl_storage_impl, secmod_impl, slots_storage_impl

// Security module can be initialized by software implementation
secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

STATUS_CHECK(vs_provision_init(&tl_storage_impl, secmod_impl), "Unable to initialize Provision Module");

// Operations

vs_provision_deinit();

 * \endcode
 *
 * Storage implementation for Trust List and Slots is described in \ref storage_hal .
 *
 * Trust List enumeration is done by #vs_provision_tl_find_first_key first call and subsequent
#vs_provision_tl_find_next_key ones.
 * Code below calculates IoT device keys amount :
 *
 * \code

vs_provision_tl_find_ctx_t search_ctx;      // Used by subsequent find first / next calls
uint8_t *public_key;                        // Public key pointer
uint16_t public_key_size;                   // Public key size
uint8_t *meta_info;                         // Meta information pointer
uint16_t meta_info_size;                    // Meta information size
size_t keys_amount = 0;                     // Keys amount
vs_pubkey_dated_t *pubkey_dated;            // Pointer to #vs_pubkey_dated_t structure

if( vs_provision_tl_find_first_key(&search_ctx, VS_KEY_IOT_DEVICE, &pubkey_dated, &public_key, &public_key_size,
&meta_info, &meta_info_size) == VS_CODE_OK ) {
    ++keys_amount;  // First key

    while( vs_provision_tl_find_next_key(&search_ctx, &pubkey_dated, &public_key, &public_key_size, &meta_info,
&meta_info_size) == VS_CODE_OK ) {
        ++keys_amount;  // Next key
    }
}

 * \endcode
 */

#ifndef VS_IOT_PROVISION_H
#define VS_IOT_PROVISION_H

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/provision/provision-structs.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/storage_hal/storage_hal.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Provision initialization
 *
 * This function must be called before any other Provision call.
 *
 * \param[in] tl_storage_ctx Storage context. Must not be NULL.
 * \param[in] secmodule Security Module implementation. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_init(vs_storage_op_ctx_t *tl_storage_ctx, vs_secmodule_impl_t *secmodule, vs_provision_events_t events_cb);

/** Provision destruction
 *
 * This function must be called after all other Provision calls.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_deinit(void);

/** Get slot number
 *
 * This function returns slot number for specified provision element.
 * \param[in] id Provision element.
 * \param[out] slot Slot number storage. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_get_slot_num(vs_provision_element_id_e id, uint16_t *slot);

/** Search high level public key
 *
 * This function searches for the same key in its own slots and returns #VS_CODE_OK if such key has been found.
 *
 * \param[in] key_type Key type.
 * \param[in] ec_type Elliptic curve type.
 * \param[in] key Key to be checked. Must not be NULL.
 * \param[in] key_sz Key size. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_search_hl_pubkey(vs_key_type_e key_type,
                              vs_secmodule_keypair_type_e ec_type,
                              const uint8_t *key,
                              uint16_t key_sz);

/** Verify high level public key
 *
 * This function verifies key to be signed.
 *
 * \param[in] key_to_check Key to check. Must not be NULL.
 * \param[in] key_size Key size. Must not be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_provision_verify_hl_key(const uint8_t *key_to_check, uint16_t key_size);

/** Get Thing service URL
 *
 * This function returns Cloud URL for Thing service.
 *
 * \return ASCIIZ URL or NULL in case of error
 */
const char *
vs_provision_cloud_url(void);

/** Find first key
 *
 * This function finds the first \a key_type key and returns it with meta information if present.
 * You can find next key by #vs_provision_tl_find_next_key call.
 *
 * \param[out] search_ctx Search context initialized by this function. Must not be NULL.
 * \param[in] key_type Key type to be found
 * \param[out] pubkey Public key pointer. Must not be NULL.
 * \param[out] pubkey_sz Public key size. Must not be NULL.
 * \param[out] meta Meta information pointer. Must not be NULL.
 * \param[out] meta_sz Meta information size. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 *
 */
vs_status_e
vs_provision_tl_find_first_key(vs_provision_tl_find_ctx_t *search_ctx,
                               vs_key_type_e key_type,
                               vs_pubkey_dated_t **pubkey_dated,
                               uint8_t **pubkey,
                               uint16_t *pubkey_sz,
                               uint8_t **meta,
                               uint16_t *meta_sz);

/** Find Next key
 *
 * This function finds the next \a key_type key and returns it with meta information if present.
 * First key must be found before by #vs_provision_tl_find_first_key call.
 *
 * \param[out] search_ctx Search context initialized by this function. Must not be NULL.
 * \param[in] key_type Key type to be found
 * \param[out] pubkey Public key pointer. Must not be NULL.
 * \param[out] pubkey_sz Public key size. Must not be NULL.
 * \param[out] meta Meta information pointer. Must not be NULL.
 * \param[out] meta_sz Meta information size. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 *
 */
vs_status_e
vs_provision_tl_find_next_key(vs_provision_tl_find_ctx_t *search_ctx,
                              vs_pubkey_dated_t **pubkey_dated,
                              uint8_t **pubkey,
                              uint16_t *pubkey_sz,
                              uint8_t **meta,
                              uint16_t *meta_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_IOT_PROVISION_H