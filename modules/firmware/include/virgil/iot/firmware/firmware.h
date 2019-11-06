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

/*! \file firmware.h
 * \brief Firmware uploading/downloading and installation implementation
 *
 * Firmware library is used to save firmware by gateway for different devices and downloading, installing them by
 * client.
 */

#ifndef VS_FIRMWARE_H
#define VS_FIRMWARE_H

#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/hsm/hsm.h>

/** Firmware descriptor */
typedef struct __attribute__((__packed__)) {
    vs_file_info_t info;      /**< File information */
    uint8_t padding;          /**< Padding */
    uint16_t chunk_size;      /**< Chunk size */
    uint32_t firmware_length; /**< Firmware length */
    uint32_t app_size;        /**< Application size = firmware_length + fill_size + footer */
} vs_firmware_descriptor_t;

/** Firmware footer */
typedef struct __attribute__((__packed__)) {
    uint8_t signatures_count;            /**< Signatures amount */
    vs_firmware_descriptor_t descriptor; /**< Firmware descriptor */
    uint8_t signatures[];                /**< Array of signatures */
} vs_firmware_footer_t;

/** Firmware header */
typedef struct __attribute__((__packed__)) {
    uint32_t code_offset;                /**< Code offset = sizeof(vs_firmware_header_t) */
    uint32_t code_length;                /**< Code length = #vs_firmware_descriptor_t . firmware_length */
    uint32_t footer_offset;              /**< Footer offset = \a code_offset + \a code_length */
    uint32_t footer_length;              /**< Footer length */
    uint8_t signatures_count;            /**< Signatures amount */
    vs_firmware_descriptor_t descriptor; /**< Firnware descriptor */
} vs_firmware_header_t;

/** Initialize firmware
 *
 * \param[in] ctx #vs_storage_op_ctx_t storage context. Must not be NULL.
 * \param[in] hsm #vs_hsm_impl_t HSM implementation. Must not be NULL.
 * \param[in] manufacture Manufacture ID
 * \param[in] device_type Device type
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_init(vs_storage_op_ctx_t *ctx,
                 vs_hsm_impl_t *hsm,
                 vs_device_manufacture_id_t manufacture,
                 vs_device_type_t device_type);

/**  Destroys firmware */
vs_status_e
vs_firmware_deinit(void);

/** Save firmware data
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 * \param[in] chunk Data buffer. Must not be NULL.
 * \param[in] chunk_sz Data size. Must not be zero.
 * \param[in] offset Data offset.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_save_firmware_chunk(const vs_firmware_descriptor_t *descriptor,
                                const uint8_t *chunk,
                                size_t chunk_sz,
                                size_t offset);

/** Save firmware footer
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 * \param[in] footer Firmware footer. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_save_firmware_footer(const vs_firmware_descriptor_t *descriptor, const uint8_t *footer);

/** Load firmware data
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 * \param[in] offset Data offset.
 * \param[out] data Data to save data. Must not be NULL.
 * \param[in] buf_sz Buffer size.
 * \param[out] data_sz Stored data size. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_load_firmware_chunk(const vs_firmware_descriptor_t *descriptor,
                                uint32_t offset,
                                uint8_t *data,
                                size_t buf_sz,
                                size_t *data_sz);

/** Load firmware footer
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 * \param[out] data Buffer to store firmware. Must not be NULL.
 * \param[in] buff_sz Buffer size. Must not be zero.
 * \param[out] data_sz Saved footer size. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_load_firmware_footer(const vs_firmware_descriptor_t *descriptor,
                                 uint8_t *data,
                                 size_t buff_sz,
                                 size_t *data_sz);

/** Verify firmware
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_verify_firmware(const vs_firmware_descriptor_t *descriptor);

/** Save firmware descriptor
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_save_firmware_descriptor(const vs_firmware_descriptor_t *descriptor);

/** Get own firmware descriptor
 *
 * \param[out] descriptor #vs_firmware_descriptor_t Output own firmware descriptor. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_get_own_firmware_descriptor(vs_firmware_descriptor_t *descriptor);

/** Load firmware descriptor
 *
 * \param[in] manufacture_id Manufactured ID.
 * \param[in] device_type Device type.
 * \param[out] descriptor #vs_firmware_descriptor_t Output firmware descriptor. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_load_firmware_descriptor(const uint8_t manufacture_id[VS_DEVICE_MANUFACTURE_ID_SIZE],
                                     const uint8_t device_type[VS_DEVICE_TYPE_SIZE],
                                     vs_firmware_descriptor_t *descriptor);

/** Delete firmware
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_delete_firmware(const vs_firmware_descriptor_t *descriptor);

/** Install firmware
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_install_firmware(const vs_firmware_descriptor_t *descriptor);

/** Describe version
 *
 * \param[in] fw_ver #vs_file_version_t File version. Must not be NULL.
 * \param[out] buffer Output buffer. Must not be NULL.
 * \param[int] buf_size Buffer size. Must not be zero.
 *
 * \return Buffer with description stored in \buffer
 */
char *
vs_firmware_describe_version(const vs_file_version_t *fw_ver, char *buffer, size_t buf_size);

/** Compare own version with given one
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_sdmp_service_t SDMP service description. Use this pointer to call #vs_sdmp_register_service.
 */
vs_status_e
vs_firmware_compare_own_version(const vs_firmware_descriptor_t *new_descriptor);

/** Get expected footer length */
int
vs_firmware_get_expected_footer_len(void);

/** Return update interface */
vs_update_interface_t *
vs_firmware_update_ctx(void);

/** Return update file type */
const vs_update_file_type_t *
vs_firmware_update_file_type(void);

/** ntoh convertor for descriptor
 *
 * \param[in,out] desc firmware descriptor. Must not be NULL.
 */
void
vs_firmware_ntoh_descriptor(vs_firmware_descriptor_t *desc);

/** ntoh convertor for header
 *
 * \param[in,out] header firmware header. Must not be NULL.
 */
void
vs_firmware_ntoh_header(vs_firmware_header_t *header);

/** hton convertor for descriptor
 *
 * \param[in,out] desc firmware descriptor. Must not be NULL.
 */
void
vs_firmware_hton_descriptor(vs_firmware_descriptor_t *desc);

/** hton convertor for header
 *
 * \param[in,out] header firmware header. Must not be NULL.
 */
void
vs_firmware_hton_header(vs_firmware_header_t *header);
#endif // VS_FIRMWARE_H
