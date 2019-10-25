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

/*! \file update.h
 * \brief Update interface for files downloading
 *
 * This file declares \a vs_update_interface_t interface that is used for files downloading by client and sending by
 * server. If you want to download/upload your own file type, you have to implement function callbacks for this interface.
 * Also there are some utilities for Update library
 */

#ifndef VS_UPDATE_H
#define VS_UPDATE_H

#include <global-hal.h>
#include <stdbool.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/provision/provision.h>

/** File types */
enum vs_update_file_type_id_t {
    VS_UPDATE_FIRMWARE, /**< Firmware files for different manufactures and device types */
    VS_UPDATE_TRUST_LIST, /**< Trust List files */
    VS_UPDATE_USER_FILES = 256 /**< User file types must have an identifier that is not lower than this code */
};

/** File type information */
typedef struct __attribute__((__packed__)) {
    uint16_t type; /**< #vs_update_file_type_id_t */
    vs_file_info_t info; /**< Additional file information */
} vs_update_file_type_t;

struct vs_update_interface_t;

/** Describe file type
 *
 * \param[in] file_type File type. Cannot be NULL.
 * \param[in] update_context Update interface for current file type. Cannot be NULL.
 * \param[out] buf Buffer to store description. Cannot be NULL.
 * \param[in] buf_size Output buffer size. Must not be zero.
 *
 * \return Output buffer \a buf with file type description or NULL in case of error.
 */
char *
vs_update_type_descr(vs_update_file_type_t *file_type, const struct vs_update_interface_t *update_context, char *buf, size_t buf_size);

/** Compare two file types
 *
 * \param file_type Known file type. Cannot be NULL.
 * \param unknown_file_type Unknown file type. Cannot be NULL.
 *
 * \return tru if file types are equal or false otherwise
 */
bool
vs_update_equal_file_type(vs_update_file_type_t *file_type, const vs_update_file_type_t *unknown_file_type);

/** Compare two files version
 *
 * \param update_ver File to be update. Cannot be NULL.
 * \param current_ver Current file version. Cannot be NULL.
 *
 * \return #VS_CODE_OK if \a update_ver file is newer than \a current_ver file.
 * \return #VS_CODE_OLD_VERSION if \a update_ver file is not newer than \a current_ver file.
 * \return Other #vs_status_e in case of error.
 */
vs_status_e
vs_update_compare_version(const vs_file_version_t *update_ver, const vs_file_version_t *current_ver);

/** Get file type header size callback
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[out] header_size Output buffer for current file type header size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_get_header_size_cb_t)(void *context, vs_update_file_type_t *file_type, size_t *header_size);

/** Get file size
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] file_header File header.
 * \param[out] file_size Output buffer to store file size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_get_file_size_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, size_t *file_size);

/** Checks that such file type has footer
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[out] has_footer Output boolean footer to store true if current file type has footer. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_has_footer_cb_t)(void *context, vs_update_file_type_t *file_type, bool *has_footer);

/** Increment data offset
 *
 * This callback return next file offset in subsequent load calls.
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] current_offset File offset for loading before this call.
 * \param[in] loaded_data_size Data size that has been loaded before this call.
 * \param[out] next_offset Output buffer to store offset for next call. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_inc_data_offset_cb_t)(void *context, vs_update_file_type_t *file_type, size_t current_offset, size_t loaded_data_size, size_t *next_offset);

/** Get file header
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[out] header_buffer Output buffer to save file header. Cannot be NULL.
 * \param[in] buffer_size Buffer size. Cannot be zero.
 * \param[out] header_size Output buffer to save header size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_get_header_cb_t)(void *context, vs_update_file_type_t *file_type, void *header_buffer, size_t buffer_size, size_t *header_size);

/** Get file data
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] file_header Current file header. Cannot be NULL.
 * \param[in] data_buffer Data buffer. Cannot be NULL.
 * \param[in] buffer_size Data size. Cannot be zero.
 * \param[out] data_size Data buffer to store read data size. Cannot be NULL.
 * \param[in] data_offset Data offset. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_get_data_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, void *data_buffer, size_t buffer_size, size_t *data_size, size_t data_offset);

/** Get footer
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] file_header Current file header. Cannot be NULL.
 * \param[out] footer_buffer Output footer buffer. Cannot be NULL.
 * \param[in] buffer_size Buffer size. Cannot be zero.
 * \param[out] footer_size Footer size that has been read. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_get_footer_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, void *footer_buffer, size_t buffer_size, size_t *footer_size);

/** Set header
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] file_header Current file header. Cannot be NULL.
 * \param[in] header_size Header size to be saved. Cannot be NULL.
 * \param[out] file_size Output buffer to store current file size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_set_header_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, size_t header_size, size_t *file_size);

/** Set data
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] file_header Current file header. Cannot be NULL.
 * \param[in] file_data Data to be saved. Cannot be NULL.
 * \param[in] data_size Data size. Cannot be NULL.
 * \param[in] data_offset Data offset from the file beginning. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_set_data_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, const void *file_data, size_t data_size, size_t data_offset);

/** Set footer
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] file_header Current file header. Cannot be NULL.
 * \param[in] file_footer Current file footer. Cannot be NULL.
 * \param[in] footer_size Footer size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_update_set_footer_cb_t)(void *context, vs_update_file_type_t *file_type, const void *file_header, const void *file_footer, size_t footer_size);

/** Is file newer that current one
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] available_file Available file version. Cannot be NULL.
 * \param[in] new_file New file version. Cannot be NULL.
 *
 * \return true if \new_file is newer than \a available_file
 */
typedef bool (*vs_update_file_is_newer_cb_t)(void *context, vs_update_file_type_t *file_type, const vs_file_version_t *available_file, const vs_file_version_t *new_file);

/** Free item during update destroy
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type.  Cannot be NULL.
 */
typedef void (*vs_update_free_item_cb_t)(void *context, vs_update_file_type_t *file_type);

/** Describe file type
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[out] buffer Output buffer to describe current file type. Cannot be NULL.
 * \param[in] buf_size Buffer size. Cannot be zero.
 *
 * \return \a buffer with file type description
 */
typedef char* (*vs_update_describe_type_cb_t)(void *context, vs_update_file_type_t *file_type, char *buffer, size_t buf_size);

/** Describe file version
 *
 * \param[in] context File context.
 * \param[in] file_type Current file type. Cannot be NULL.
 * \param[in] version Current file version. Cannot be NULL.
 * \param[out] buffer Output buffer to store file version description. Cannot be NULL.
 * \param[in] buf_size Output buffer size. Cannot be zero.
 * \param[in] add_filetype_description If true, \a vs_update_describe_type_cb_t is called and stored to the \a buffer before current file version description
 *
 * \return \a buffer with file type description
 */
typedef char* (*vs_update_describe_version_cb_t)(void *context, vs_update_file_type_t *file_type, const vs_file_version_t *version, char *buffer, size_t buf_size, bool add_filetype_description);

/** Update interface context */
typedef struct __attribute__((__packed__)) vs_update_interface_t {
    vs_update_get_header_size_cb_t    get_header_size; /**< Get header callback */
    vs_update_get_file_size_cb_t      get_file_size; /**< Get file size callback */
    vs_update_has_footer_cb_t         has_footer; /**< Has footer callback */
    vs_update_inc_data_offset_cb_t    inc_data_offset; /**< Increment data offste callback */

    vs_update_get_header_cb_t         get_header; /**< Get header callback */
    vs_update_get_data_cb_t           get_data; /**< Get data callback */
    vs_update_get_footer_cb_t         get_footer; /**< Get footer callback */

    vs_update_set_header_cb_t         set_header; /**< Set header callback */
    vs_update_set_data_cb_t           set_data; /**< Set data callback */
    vs_update_set_footer_cb_t         set_footer; /**< Set footer callback */

    vs_update_free_item_cb_t          free_item; /**< Free item callback */

    vs_update_file_is_newer_cb_t      file_is_newer; /**< File is newer callback */
    vs_update_describe_type_cb_t      describe_type; /**< Describe file type callback */
    vs_update_describe_version_cb_t   describe_version; /**< Describe file version callback */

    vs_storage_op_ctx_t *storage_context; /**< Storage context */

} vs_update_interface_t;

#endif // VS_UPDATE_H
