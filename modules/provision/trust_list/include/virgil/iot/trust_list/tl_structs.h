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

/*! \file tl_structs.h
 * \brief Trust List structures
 */

#ifndef TL_STRUCTS_H
#define TL_STRUCTS_H

#include <stdint.h>
#include <stdbool.h>
#include <virgil/iot/provision/provision.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Trust List storage types */
typedef enum {
    TL_STORAGE_TYPE_STATIC = 0, /**< Default Trust List backup for restoring it in case of provision error */
    TL_STORAGE_TYPE_DYNAMIC,    /**< Trust List during the provision process */
    TL_STORAGE_TYPE_TMP,        /**< Trust list that is loading. After successful verification it is saved to \a
                                   TL_STORAGE_TYPE_STATIC */
} vs_tl_storage_t;

typedef size_t vs_tl_key_handle;

/** Trust List header */
typedef struct __attribute__((__packed__)) {
    uint32_t tl_size;          /**< Trust List size = header + public keys + footer */
    vs_file_version_t version; /**< Version */
    uint16_t pub_keys_count;   /**< Public keys amount */
    uint8_t signatures_count;  /**< Signatures amount */
} vs_tl_header_t;

/** Trust List footer */
typedef struct __attribute__((__packed__)) {
    uint8_t tl_type;      /**< Trust List type */
    uint8_t signatures[]; /**< Signatures */
} vs_tl_footer_t;

typedef enum {
    VS_TL_ELEMENT_MIN = 0,
    VS_TL_ELEMENT_TLH,
    VS_TL_ELEMENT_TLC,
    VS_TL_ELEMENT_TLF,
    VS_TL_ELEMENT_MAX,
} vs_tl_element_e;

typedef struct vs_tl_element_info_s {
    vs_tl_element_e id;
    int index;
} vs_tl_element_info_t;

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // TL_STRUCTS_H
