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

/*! \file firmware.h
 * \brief Firmware uploading/downloading and installation implementation
 *
 * Devices use Firmware library to delete, verify and install firmware obtained from Gateway (Thing devices) or cloud
 * (Gateway devices).
 *
 * \section firmware_usage_gateway Firmware Usage by Gateway
 *
 * Gateway uses Firmware library for different purposes :
 * - Download firmware from Cloud storage, verify and save it.
 * - Install firmware for current Gateway.
 * - Upload firmware for different devices inside the network by using FLDT Server service.
 *
 * First of all it is necessary to initialize Firmware library :
 *
 * \code

vs_storage_op_ctx_t fw_storage_impl;                // Firmware storage implementation
vs_secmodule_impl_t *secmodule_impl = NULL;         // Security module implementation
static vs_device_manufacture_id_t manufacture_id;   // Manufacture ID
static vs_device_type_t device_type;                // Device type

// Initialize fw_storage_impl, manufacture_id, device_type

// Virgil IoT KIT provides Software Security Module that can be used instead of Hardware one :
secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

STATUS_CHECK(vs_firmware_init(&fw_storage_impl, secmodule_impl, manufacture_id, device_type), "Unable to initialize
Firmware module");

 * \endcode
 *
 * Firmware storage implementation \a fw_storage_impl initialization is described in \ref storage_hal section.
 *
 * You can use software security module #vs_soft_secmodule_impl() as it is done in this example.
 *
 * \a manufacture_id, \a device_type are device unique characteristics and can be initialized by compile time constants.
 * See \ref provision_structures_usage for details
 *
 * For FLDT Server service (see \ref fldt_server_usage for details) it is necessary to implement
 * #vs_fldt_server_add_filetype_cb. Also it is necessary to add Firmware file type to the supported file types
 * list by calling #vs_fldt_server_add_file_type() :
 *
 * \code
 *
vs_status_e
_add_filetype(const vs_update_file_type_t *file_type, vs_update_interface_t **update_ctx) {
    switch (file_type->type) {
    case VS_UPDATE_FIRMWARE:    // Firmware file request
        *update_ctx = vs_firmware_update_ctx();     // Firmware's Update context
        break;
    case VS_UPDATE_TRUST_LIST:  // Trust List file request
        *update_ctx = vs_tl_update_ctx();           // Trust List's Update context
        break;
    default:                    // Unsupported file type request
        VS_LOG_ERROR("Unsupported file type : %d", file_type->type);
        return VS_CODE_ERR_UNSUPPORTED_PARAMETER;
    }

    return VS_CODE_OK;
}

// Initialize mac_addr by current device MAC address

snap_fldt_server = vs_snap_fldt_server(&mac_addr, _add_filetype);

STATUS_CHECK(vs_fldt_server_add_file_type(vs_firmware_update_file_type(), vs_firmware_update_ctx(), false),
            "Unable to add firmware file type");

 * \endcode
 *
 * In this example \a _add_filetype processes 2 standard file types. One of them is Firmware file type.
 *
 * Gateway receives firmwares for different targets from Cloud. It necessary to verify them and to broadcast information
 * about the new firmware by using FLDT Server service :
 *
 * \code

vs_firmware_header_t header;        // Firmware header
const char *upd_file_url;           // URL for file update
vs_update_file_type_t fw_info;      // Update file information
int res;

// Initialize upd_file_url by download address

res = vs_cloud_fetch_and_store_fw_file(upd_file_url, &header);
if (VS_CODE_OK == res) {
    res = vs_firmware_verify_firmware(&header.descriptor);
    if (VS_CODE_OK == res) {
        fw_info.type = VS_UPDATE_FIRMWARE;
        memcpy(&fw_info.info, &header.descriptor.info, sizeof(vs_file_info_t));
        if(_is_self_firmware_image(&fw_info.info){
            _process_own_firmware(&header);
        } else {
            STATUS_CHECK(vs_fldt_server_add_file_type(&fw_info, vs_firmware_update_ctx(), true), "Unable to add new
firmware");
        }
    } else {
        vs_firmware_delete_firmware(&header.descriptor);
    }

}

 * \endcode
 *
 * In this example Gateway receives firmware header by using Cloud module (see \ref cloud_usage for details ). It
 * verifies the received firmware. In case of error it deletes the firmware. In another case it analyzes this firmware
type
 * (\a _is_self_firmware_image call). If this firmware is intended for this gateway, the gateway installs it
 * (\a _process_own_firmware call). Otherwise it sends firmware to devices by using FLDT Server service
 * (#vs_fldt_server_add_file_type() call) :
 *
 * \code

bool
_is_self_firmware_image(vs_file_info_t *fw_info) {
    vs_firmware_descriptor_t desc;
    STATUS_CHECK_RET_BOOL(vs_firmware_get_own_firmware_descriptor(&desc), "Unable to get own firmware descriptor");

    return (0 == VS_IOT_MEMCMP(desc.info.manufacture_id, fw_info->manufacture_id, sizeof(desc.info.manufacture_id)) &&
            0 == VS_IOT_MEMCMP(desc.info.device_type, fw_info->device_type, sizeof(desc.info.device_type)));
}

void
_process_own_firmware(vs_firmware_header_t *fw_info, vs_firmware_header_t *header){
    vs_firmware_descriptor_t desc;
    if ( VS_CODE_OK == vs_firmware_load_firmware_descriptor(fw_info->manufacture_id, request->device_type, &desc) &&
        VS_CODE_OK == vs_firmware_install_firmware(&desc) ) // Installs application
        {
            // Restart application or reboot in case of MCU
        }
}

void
_send_firmware(){
    if (vs_fldt_server_add_file_type(queued_file, vs_firmware_update_ctx(), true)) {
        VS_LOG_ERROR("Unable to add new firmware");
        // Error processing
    }
}

 * \endcode
 *
 *
 * \section firmware_usage_thing Firmware Usage by Thing
 *
 * All Firmware functionality for Thing is implemented by Virgil IoT KIT. User only needs to initialize Firmware library
 * and destroy it at the end. See code example below :
 *
 * \code

vs_storage_op_ctx_t fw_storage_impl;    // Firmware storage implementation
vs_secmodule_impl_t *secmodule_impl = NULL;         // Security module implementation
static vs_device_manufacture_id_t manufacture_id;   // Manufacture ID
static vs_device_type_t device_type;                // Device type

// Initialize manufacture_id, device_type

secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);   // Use Software Security Module

STATUS_CHECK(vs_firmware_init(&fw_storage_impl, secmodule_impl, manufacture_id, device_type), "Unable to initialize
Firmware module");

 * \endcode
 *
 * Firmware storage implementation \a fw_storage_impl initialization is described in \ref storage_hal section.
 *
 * Security module implementation \a secmodule_impl initialization is described in \ref storage_hal section. You can use
 * software security module #vs_soft_secmodule_impl() as shown in the example above.
 *
 * \a manufacture_id, \a device_type are device unique characteristics and can be initialized by compile time constants.
 * See \ref provision_structures_usage for details
 */

#ifndef VS_FIRMWARE_H
#define VS_FIRMWARE_H

#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/secmodule/secmodule.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

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
 * Firmware initialization has to be done before first Firmware calls.
 *
 * \param[in] ctx #vs_storage_op_ctx_t storage context. Must not be NULL.
 * \param[in] secmodule #vs_secmodule_impl_t Security Module implementation. Must not be NULL.
 * \param[in] manufacture Manufacture ID
 * \param[in] device_type Device type
 * \param[out] ver Pointer to #vs_file_version_t. Will be filled by a current version of firmware.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_init(vs_storage_op_ctx_t *storage_ctx,
                 vs_secmodule_impl_t *secmodule,
                 vs_device_manufacture_id_t manufacture,
                 vs_device_type_t device_type,
                 vs_file_version_t *ver);

/**  Destroy firmware module
 *
 * It has to be executed before application finish.
 *
 */
vs_status_e
vs_firmware_deinit(void);

/** Save firmware data
 *
 * Gateway saves a chunk of data received from Cloud. Thing automatically saves the chunk of data received from Gateway.
 *
 * See \ref firmware_usage_gateway for data flow details.
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 * \param[in] chunk Data buffer. Must not be NULL.
 * \param[in] chunk_sz Data size. Must not be zero.
 * \param[in] offset Data offset.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_save_firmware_chunk(const vs_firmware_descriptor_t *descriptor,
                                const uint8_t *chunk,
                                size_t chunk_sz,
                                size_t offset);

/** Save firmware footer
 *
 * Gateway saves firmware footer received from Cloud. Thing automatically saves footer firmware received from Gateway.
 *
 * See \ref firmware_usage_gateway for data flow details.
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 * \param[in] footer Firmware footer. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_save_firmware_footer(const vs_firmware_descriptor_t *descriptor, const uint8_t *footer);

/** Load firmware data
 *
 * Gateway loads a chunk of data to send it to Thing.
 *
 * See \ref firmware_usage_gateway for data flow details.
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 * \param[in] offset Data offset.
 * \param[out] data Data to save data. Must not be NULL.
 * \param[in] buf_sz Buffer size.
 * \param[out] data_sz Stored data size. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_load_firmware_chunk(const vs_firmware_descriptor_t *descriptor,
                                uint32_t offset,
                                uint8_t *data,
                                size_t buf_sz,
                                size_t *data_sz);

/** Load firmware footer
 *
 * Gateway loads firmware footer to send it to Thing.
 *
 * See \ref firmware_usage_gateway for data flow details.
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 * \param[out] data Buffer to store firmware in. Must not be NULL.
 * \param[in] buff_sz Buffer size. Must not be zero.
 * \param[out] data_sz Saved footer size. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_load_firmware_footer(const vs_firmware_descriptor_t *descriptor,
                                 uint8_t *data,
                                 size_t buff_sz,
                                 size_t *data_sz);

/** Verify firmware
 *
 * Gateway verifies firmware received from Cloud. Thing verifies firmware before its installation.
 *
 * See \ref firmware_usage_gateway for data flow details.
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_verify_firmware(const vs_firmware_descriptor_t *descriptor);

/** Save firmware descriptor
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_save_firmware_descriptor(const vs_firmware_descriptor_t *descriptor);

/** Get own firmware descriptor
 *
 * Gets own firmware description by both Gateway and Thing.
 *
 * \param[out] descriptor #vs_firmware_descriptor_t Output own firmware descriptor. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_get_own_firmware_descriptor(vs_firmware_descriptor_t *descriptor);

/** Load firmware descriptor
 *
 * Gets firmware descriptor for specified manufacture and device type.
 *
 * \param[in] manufacture_id Manufacture ID.
 * \param[in] device_type Device type.
 * \param[out] descriptor #vs_firmware_descriptor_t Output firmware descriptor. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_load_firmware_descriptor(const uint8_t manufacture_id[VS_DEVICE_MANUFACTURE_ID_SIZE],
                                     const uint8_t device_type[VS_DEVICE_TYPE_SIZE],
                                     vs_firmware_descriptor_t *descriptor);

/** Delete firmware
 *
 * Thing automatically deletes firmware in case of invalid data.
 *
 * See \ref firmware_usage_gateway for data flow details.
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_delete_firmware(const vs_firmware_descriptor_t *descriptor);

/** Install firmware
 *
 * Thing automatically installs firmware in case of successful verification.
 *
 * See \ref firmware_usage_gateway for data flow details.
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_install_firmware(const vs_firmware_descriptor_t *descriptor);

/** Compare own firmware version with the given one
 *
 * Thing automatically compares its own version with the \a new_descriptor one.
 *
 * See \ref firmware_usage_gateway for data flow details.
 *
 * \param[in] descriptor #vs_firmware_descriptor_t firmware descriptor. Must not be NULL.
 *
 * \return #vs_snap_service_t SNAP service description. Use this pointer to call #vs_snap_register_service.
 */
vs_status_e
vs_firmware_compare_own_version(const vs_firmware_descriptor_t *new_descriptor);

/** Get expected firmware footer length
 *
 * This call returns firmware footer length.
 *
 * \return Firmware length in bytes
 */
int
vs_firmware_get_expected_footer_len(void);

/** Return firmware Update interface
 *
 * This call returns Update implementation. It is used for Update calls.
 *
 * \return Update interface implementation
 *
 */
vs_update_interface_t *
vs_firmware_update_ctx(void);

/** Return firmware file type for Update library
 *
 * This call returns file type information for Update library. It is used for Update calls.
 *
 * \return File type information for Update library
 *
 */
const vs_update_file_type_t *
vs_firmware_update_file_type(void);

/** ntoh conversion for descriptor
 *
 * This call makes network-to-host firmware descriptor conversion.
 *
 * \warning This call changes \a desc input parameter.
 *
 * \param[in,out] desc firmware descriptor. Must not be NULL.
 */
void
vs_firmware_ntoh_descriptor(vs_firmware_descriptor_t *desc);

/** ntoh conversion for header
 *
 * This call makes network-to-host firmware header conversion.
 *
 * \warning This call changes \a desc input parameter.
 *
 * \param[in,out] desc firmware descriptor. Must not be NULL.
 */
void
vs_firmware_ntoh_header(vs_firmware_header_t *header);

/** hton conversion for descriptor
 *
 * This call makes host-to-network firmware descriptor conversion.
 *
 * \warning This call changes \a desc input parameter.
 *
 * \param[in,out] desc firmware descriptor. Must not be NULL.
 */
void
vs_firmware_hton_descriptor(vs_firmware_descriptor_t *desc);

/** hton conversion for header
 *
 * This call makes host-to-network firmware header conversion.
 *
 * \warning This call changes \a desc input parameter.
 *
 * \param[in,out] desc firmware descriptor. Must not be NULL.
 */
void
vs_firmware_hton_header(vs_firmware_header_t *header);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_FIRMWARE_H
