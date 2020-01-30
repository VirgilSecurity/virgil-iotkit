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

/*! \file provision-structs.h
 * \brief Provision interface structures
 *
 * \section provision_structures_usage Provision structures usage
 *
 * See \ref provision_usage for Provision module initialization and call.
 *
 * Device has 3 identifiers that are used by Cloud and Update interfaces : manufacture ID, device type and device serial
number,
 * #vs_device_manufacture_id_t, #vs_device_type_t and #vs_device_serial_t respectively. They must be initialized before
 * any Virgil IoT calls.
 *
 * Manufacture ID initialization example provided below :
 *
 * \code

void
init_manufacture_id(vs_device_manufacture_id_t manufacture_id, void *src_data) {
    size_t pos;
    const uint8_t *raw_data = src_data;

    memset(manufacture_id, 0, sizeof(vs_device_manufacture_id_t));

    for (pos = 0; pos < sizeof(vs_device_manufacture_id_t) && raw_data[pos]; ++pos) {
        manufacture_id[pos] = raw_data[pos];
    }
}

// in main:
vs_device_manufacture_id_t manufacture_id;

// MANUFACTURE_ID is the compile time ASCII constant provided by -D compilation parameter
init_manufacture_id(manufacture_id, MANUFACTURE_ID);

 * \endcode
 *
 * You can use function like this for device type filling and device serial number.
 *
 */

#ifndef VS_IOT_PROVISION_STRUCTS_H
#define VS_IOT_PROVISION_STRUCTS_H

#include <virgil/iot/status_code/status_code.h>
#include <trust_list-config.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HTONL_IN_COMPILE_TIME(val)                                                                                     \
    (uint32_t)(((uint32_t)val & 0xFF) << 24 | ((uint32_t)val & 0xFF00) << 8 | ((uint32_t)val & 0xFF0000) >> 8 |        \
               ((uint32_t)val & 0xFF000000) >> 24)
#else
#define HTONL_IN_COMPILE_TIME(val) (val)
#endif

// Macro used to do htons in compile time
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HTONS_IN_COMPILE_TIME(val) (uint16_t)(((uint16_t)val & 0xFF) << 8 | ((uint16_t)val & 0xFF00) >> 8)
#else
#define HTONS_IN_COMPILE_TIME(val) (val)
#endif

/** The start time point for UNIX time format
 *
 * Timestamps are stored as seconds since January 1, 2015 UTC. This is constant for UNIX time conversions
 */
#define VS_START_EPOCH (1420070400)

/** Device serial ID size */
#define VS_DEVICE_SERIAL_SIZE (32)

/** Manufacture ID size */
#define VS_DEVICE_MANUFACTURE_ID_SIZE (16)

/** Device type size */
#define VS_DEVICE_TYPE_SIZE (4)

/** Manufacture ID type
 *
 * Manufacture identifier containing ASCII symbols and trailing zeroes.
 */
typedef uint8_t vs_device_manufacture_id_t[VS_DEVICE_MANUFACTURE_ID_SIZE];

/** Device type
 *
 * Device type identifier contains ASCII symbols and trailing zeroes.
 *
 */
typedef uint8_t vs_device_type_t[VS_DEVICE_TYPE_SIZE];

/** Device serial number type
 *
 * Device serial number identifier contains ASCII symbols and trailing zeroes.
 *
 */
typedef uint8_t vs_device_serial_t[VS_DEVICE_SERIAL_SIZE];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"

/** PRVS SNAP service code */
typedef enum { VS_PRVS_SERVICE_ID = HTONL_IN_COMPILE_TIME('PRVS') } vs_prvs_t;

/** Provision operations */
typedef enum {
    VS_PRVS_DNID = HTONL_IN_COMPILE_TIME('DNID'), /**< Discover Not Initialized Devices */
    VS_PRVS_SGNP = HTONL_IN_COMPILE_TIME('SGNP'), /**< Signature of own public key (by private key VS_PRVS_PBDM)  */
    VS_PRVS_PBR1 = HTONL_IN_COMPILE_TIME('PBR1'), /**< Set Recovery Key 1 */
    VS_PRVS_PBR2 = HTONL_IN_COMPILE_TIME('PBR2'), /**< Set Recovery Key 2 */
    VS_PRVS_PBA1 = HTONL_IN_COMPILE_TIME('PBA1'), /**< Set Auth Key 1 */
    VS_PRVS_PBA2 = HTONL_IN_COMPILE_TIME('PBA2'), /**< Set Auth Key 2 */
    VS_PRVS_PBT1 = HTONL_IN_COMPILE_TIME('PBT1'), /**< Set Trust List Key 1 */
    VS_PRVS_PBT2 = HTONL_IN_COMPILE_TIME('PBT2'), /**< Set Trust List 2 */
    VS_PRVS_PBF1 = HTONL_IN_COMPILE_TIME('PBF1'), /**< Set Firmware Key 1 */
    VS_PRVS_PBF2 = HTONL_IN_COMPILE_TIME('PBF2'), /**< Set Firmware Key 2 */
    VS_PRVS_TLH = HTONL_IN_COMPILE_TIME('_TLH'),  /**< Set Trust List Header */
    VS_PRVS_TLC = HTONL_IN_COMPILE_TIME('_TLC'),  /**< Set Trust List Chunk */
    VS_PRVS_TLF = HTONL_IN_COMPILE_TIME('_TLF'),  /**< Set Trust List Footer */
    VS_PRVS_DEVI = HTONL_IN_COMPILE_TIME('DEVI'), /**< Get DEVice Info */
    VS_PRVS_ASAV = HTONL_IN_COMPILE_TIME('ASAV'), /**< Action SAVe provision */
    VS_PRVS_ASGN = HTONL_IN_COMPILE_TIME('ASGN'), /**< Action SiGN data */
} vs_snap_prvs_element_e;
#pragma GCC diagnostic pop

/** Element ID */
typedef enum {
    VS_PROVISION_SGNP = VS_PRVS_SGNP,
    VS_PROVISION_PBR1 = VS_PRVS_PBR1,
    VS_PROVISION_PBR2 = VS_PRVS_PBR2,
    VS_PROVISION_PBA1 = VS_PRVS_PBA1,
    VS_PROVISION_PBA2 = VS_PRVS_PBA2,
    VS_PROVISION_PBT1 = VS_PRVS_PBT1,
    VS_PROVISION_PBT2 = VS_PRVS_PBT2,
    VS_PROVISION_PBF1 = VS_PRVS_PBF1,
    VS_PROVISION_PBF2 = VS_PRVS_PBF2
} vs_provision_element_id_e;

/** Key type */
typedef enum {
    VS_KEY_RECOVERY = 0,      /**< Recovery key */
    VS_KEY_AUTH,              /**< Authentication key */
    VS_KEY_TRUSTLIST,         /**< Trust List key*/
    VS_KEY_FIRMWARE,          /**< Firmware key */
    VS_KEY_FACTORY,           /**< Factory key */
    VS_KEY_IOT_DEVICE,        /**< Key of IoT device */
    VS_KEY_USER_DEVICE,       /**< Key ofr user device*/
    VS_KEY_FIRMWARE_INTERNAL, /**< Firmware internal key */
    VS_KEY_AUTH_INTERNAL,     /**< Authentication internal key */
    VS_KEY_CLOUD,             /**< Cloud key */
    VS_KEY_UNSUPPORTED        /**< Unsupported key */
} vs_key_type_e;

/** Signature type */
typedef struct __attribute__((__packed__)) {
    uint8_t signer_type;       /**< #vs_key_type_e */
    uint8_t ec_type;           /**< #vs_secmodule_keypair_type_e */
    uint8_t hash_type;         /**< #vs_secmodule_hash_type_e */
    uint8_t raw_sign_pubkey[]; /**< An array with raw signature and public key, size of elements depends on \a ec_type
                                */
} vs_sign_t;

/** Public key type */
typedef struct __attribute__((__packed__)) {
    uint8_t key_type;          /**< #vs_key_type_e */
    uint8_t ec_type;           /**< #vs_secmodule_keypair_type_e */
    uint16_t meta_data_sz;     /**< Meta data size */
    uint8_t meta_and_pubkey[]; /**< Meta data and public key, size of element depends on \a ec_type */
} vs_pubkey_t;

/** Public key with date information */
typedef struct __attribute__((__packed__)) {
    uint32_t start_date;  /**< Start date */
    uint32_t expire_date; /**< Expiration date */
    vs_pubkey_t pubkey;   /**< Public key */
} vs_pubkey_dated_t;

/** File version information */
typedef struct __attribute__((__packed__)) {
    uint8_t major;      /**< Major version number */
    uint8_t minor;      /**< Minor version number */
    uint8_t patch;      /**< Patch number */
    uint32_t build;     /**< Build number */
    uint32_t timestamp; /**< The number of seconds since #VS_START_EPOCH */
} vs_file_version_t;

/** File information */
typedef struct __attribute__((__packed__)) {
    vs_device_manufacture_id_t manufacture_id; /**< Manufacture ID */
    vs_device_type_t device_type;              /**< Device type */
    vs_file_version_t version;                 /**< File version */
} vs_file_info_t;

/** Find context
 *
 * This structure is used by #vs_provision_tl_find_first_key, #vs_provision_tl_find_next_key keys. This is internal one
 * and does not need to be neither initialized nor analyzed by user.
 */
typedef struct {
    int last_pos;
    vs_key_type_e key_type;
    uint8_t element_buf[VS_TL_STORAGE_MAX_PART_SIZE];
} vs_provision_tl_find_ctx_t;

/** Callback function to inform system about current version of file
 *
 * \param[in] ver #vs_file_version_t Current version of file
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef void (*vs_file_ver_info_cb_t)(vs_file_version_t ver);

/** Container of pointers to callback functions for Provision Events
 *
 * Fill required callbacks to receive information about different events of Provision module
 */
typedef struct {
    vs_file_ver_info_cb_t tl_ver_info_cb;
} vs_provision_events_t;

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_IOT_PROVISION_STRUCTS_H