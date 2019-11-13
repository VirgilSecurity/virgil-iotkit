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

/*! \file provision-structs.h
 * \brief Provision interface structures
 *
 * \section provision_structures_usage Provision structure usage
 *
 * TODO : manufacture, device id initialization
 */

#ifndef VS_IOT_PROVISION_STRUCTS_H
#define VS_IOT_PROVISION_STRUCTS_H

#include <virgil/iot/status_code/status_code.h>
#include <trust_list-config.h>

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

/*The start time point for all timestamp variables. January 1, 2015 UTC*/
#define START_EPOCH (1420070400);

#define VS_DEVICE_SERIAL_SIZE (32) /*This is size of SHA256 data*/
#define VS_DEVICE_MANUFACTURE_ID_SIZE (16)
#define VS_DEVICE_TYPE_SIZE (4)

/** "Manufacture ID" type
 *
 * This is manufacture identifier contains ASCII symbols and trailing zeroes.
 */
typedef uint8_t vs_device_manufacture_id_t[VS_DEVICE_MANUFACTURE_ID_SIZE];
/** "Device type" type
 *
 * This is device type identifier contains ASCII symbols and trailing zeroes.
 */
typedef uint8_t vs_device_type_t[VS_DEVICE_TYPE_SIZE];

/** "Device serial number" type */
typedef uint8_t vs_device_serial_t[VS_DEVICE_SERIAL_SIZE];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
/** PRVS SDMP service code */
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
} vs_sdmp_prvs_element_e;
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

// TODO : are key description correct???
/** Key type */
typedef enum {
    VS_KEY_RECOVERY = 0,      /**< Recovery key */
    VS_KEY_AUTH,              /**< Authentification key */
    VS_KEY_TRUSTLIST,         /**< Trust List key*/
    VS_KEY_FIRMWARE,          /**< Firmware key */
    VS_KEY_FACTORY,           /**< Factory key */
    VS_KEY_IOT_DEVICE,        /**< Key of IoT device */
    VS_KEY_USER_DEVICE,       /**< Key ofr user device*/
    VS_KEY_FIRMWARE_INTERNAL, /**< Firmware internal key */
    VS_KEY_AUTH_INTERNAL,     /**< Authentification internal key */
    VS_KEY_CLOUD,             /**< Cloud key */
    VS_KEY_UNSUPPORTED        /**< Unsupported key */
} vs_key_type_e;

/** Signature type */
typedef struct __attribute__((__packed__)) {
    uint8_t signer_type;       /**< #vs_key_type_e */
    uint8_t ec_type;           /**< #vs_hsm_keypair_type_e */
    uint8_t hash_type;         /**< #vs_hsm_hash_type_e */
    uint8_t raw_sign_pubkey[]; /**< An array with raw signature and public key, size of elements depends on \a ec_type
                                */
} vs_sign_t;

/** Public key type */
typedef struct __attribute__((__packed__)) {
    uint8_t key_type;          /**< vs_key_type_e */
    uint8_t ec_type;           /**< vs_hsm_keypair_type_e */
    uint16_t meta_data_sz;     /**< Meta data size */
    uint8_t meta_and_pubkey[]; /**< Meta data and public key, size of element depends on \a ec_type */
} vs_pubkey_t;

// TODO : dates - in which units??? time_t ??? Or since 1 Jan 2015 ???
/** Public key with date information */
typedef struct __attribute__((__packed__)) {
    uint32_t start_date;  /**< Start date */
    uint32_t expire_date; /**< Expiration date */
    vs_pubkey_t pubkey;   /**< Public key */
} vs_pubkey_dated_t;

typedef struct __attribute__((__packed__)) {
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
    uint32_t build;
    uint32_t timestamp; // the number of seconds elapsed since January 1, 2015 UTC
} vs_file_version_t;

typedef struct __attribute__((__packed__)) {
    vs_device_manufacture_id_t manufacture_id;
    vs_device_type_t device_type;
    vs_file_version_t version;
} vs_file_info_t;

typedef struct {
    int last_pos;
    vs_key_type_e key_type;
    uint8_t element_buf[VS_TL_STORAGE_MAX_PART_SIZE];
} vs_provision_tl_find_ctx_t;

#endif // VS_IOT_PROVISION_STRUCTS_H