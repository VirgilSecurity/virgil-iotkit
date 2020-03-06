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

#include <defaults/storage/storage-esp-impl.h>

#include <sdkconfig.h>

#if VS_FIO_PROFILE_WRITE || VS_FIO_PROFILE_READ || VS_FIO_PROFILE_SYNC || VS_FIO_PROFILE_GETLEN || VS_FIO_PROFILE_REMOVE
#include <helpers/profiling.h>
#else
#define VS_PROFILE_START
#define VS_PROFILE_END_IN_MS(DESC)
#endif

typedef struct {
    char *dir;
} vs_esp_storage_ctx_t;

static const char *_tl_dir = "/" TL_PARTITION_NAME "/tl";
static const char *_firmware_dir = "/" FW_STORAGE_PARTITION_NAME "/fw";
static const char *_slots_dir = "/" SLOTS_PARTITION_NAME "/slt";
static const char *_secbox_dir = "/" SECBOX_PARTITION_NAME "/sb";

/******************************************************************************/
vs_status_e
vs_app_init_partition(const char *flash_part) {
    CHECK_NOT_ZERO_RET(flash_part && flash_part[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(ESP_OK == flash_data_init(flash_part), VS_CODE_ERR_FILE, "Error flash data initialization");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_app_deinit_partition(const char *flash_part) {
    CHECK_NOT_ZERO_RET(flash_part && flash_part[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(ESP_OK == flash_data_deinit(flash_part), VS_CODE_ERR_FILE, "Error unmount flash data partition");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_app_storage_init_impl(vs_storage_op_ctx_t *storage_impl, const char *base_dir, size_t file_size_max) {
    CHECK_NOT_ZERO_RET(storage_impl, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(base_dir, VS_CODE_ERR_INCORRECT_ARGUMENT);

    memset(storage_impl, 0, sizeof(*storage_impl));

    // Prepare TL storage
    storage_impl->impl_func = vs_esp_storage_impl_func();
    storage_impl->impl_data = vs_esp_storage_impl_data_init(base_dir);
    storage_impl->file_sz_limit = file_size_max;

    return VS_CODE_OK;
}

/******************************************************************************/
const char *
vs_app_trustlist_dir(void) {
    return _tl_dir;
}

/******************************************************************************/
const char *
vs_app_firmware_dir(void) {
    return _firmware_dir;
}

/******************************************************************************/
const char *
vs_app_slots_dir(void) {
    return _slots_dir;
}

/******************************************************************************/
const char *
vs_app_secbox_dir(void) {
    return _secbox_dir;
}

/******************************************************************************/
vs_storage_impl_data_ctx_t
vs_esp_storage_impl_data_init(const char *folder) {
    vs_esp_storage_ctx_t *ctx = NULL;

    CHECK_NOT_ZERO_RET(folder, NULL);

    ctx = VS_IOT_CALLOC(1, sizeof(vs_esp_storage_ctx_t));
    CHECK_NOT_ZERO_RET(ctx, NULL);

    ctx->dir = (char *)VS_IOT_CALLOC(1, strlen(folder) + 1);

    if (NULL == ctx->dir) {
        VS_LOG_ERROR("Can't allocate memory");
        VS_IOT_FREE(ctx);
        return NULL;
    }

    VS_IOT_STRCPY(ctx->dir, folder);
    VS_LOG_DEBUG("Storage folder [%s]", ctx->dir);
    // Create path
    vs_files_create_subdir(folder);

    return ctx;
}

/******************************************************************************/
static vs_status_e
_esp_storage_deinit_hal(vs_storage_impl_data_ctx_t storage_ctx) {
    vs_esp_storage_ctx_t *ctx = (vs_esp_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->dir, VS_CODE_ERR_INCORRECT_PARAMETER);

    VS_IOT_FREE(ctx->dir);
    VS_IOT_FREE(ctx);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_storage_file_t
_esp_storage_open_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_esp_storage_ctx_t *ctx = (vs_esp_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(id, NULL);
    CHECK_NOT_ZERO_RET(storage_ctx, NULL);
    CHECK_NOT_ZERO_RET(ctx->dir, NULL);
    CHECK_RET(sizeof(vs_storage_element_id_t) > strlen(ctx->dir) + 1, NULL, "File name too long");
    uint32_t len = sizeof(vs_storage_element_id_t) - strlen(ctx->dir) - 1;

    uint8_t *file = (uint8_t *)VS_IOT_CALLOC(1, len);
    CHECK_NOT_ZERO_RET(file, NULL);
    vs_files_create_filename(id, file, len);

    return file;
}

/******************************************************************************/
static vs_status_e
_esp_storage_sync_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_file_t file) {
    vs_status_e res = VS_CODE_ERR_FILE;

    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    vs_esp_storage_ctx_t *ctx = (vs_esp_storage_ctx_t *)storage_ctx;

#if VS_FIO_PROFILE_SYNC
    VS_PROFILE_START;
#endif
    if (vs_files_sync(ctx->dir, (char *)file)) {
        res = VS_CODE_OK;
    }

#if VS_FIO_PROFILE_SYNC
    VS_PROFILE_END_IN_MS("sync");
#endif

    return res;
}

/******************************************************************************/
static vs_status_e
_esp_storage_close_hal(const vs_storage_impl_data_ctx_t storage_ctx, vs_storage_file_t file) {
    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_INCORRECT_PARAMETER);

    VS_IOT_FREE(file);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_esp_storage_save_hal(const vs_storage_impl_data_ctx_t storage_ctx,
                      const vs_storage_file_t file,
                      size_t offset,
                      const uint8_t *data,
                      size_t data_sz) {

    vs_status_e res = VS_CODE_ERR_FILE_WRITE;
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_NULLPTR_ARGUMENT);
    vs_esp_storage_ctx_t *ctx = (vs_esp_storage_ctx_t *)storage_ctx;

#if VS_FIO_PROFILE_WRITE
    VS_PROFILE_START;
#endif

    if (vs_files_write(ctx->dir, (char *)file, offset, data, data_sz)) {
        res = VS_CODE_OK;
    }

#if VS_FIO_PROFILE_WRITE
    VS_PROFILE_END_IN_MS("Save");
#endif

    return res;
}

/******************************************************************************/
static vs_status_e
_esp_storage_load_hal(const vs_storage_impl_data_ctx_t storage_ctx,
                      const vs_storage_file_t file,
                      size_t offset,
                      uint8_t *out_data,
                      size_t data_sz) {
    size_t read_sz;
    vs_status_e res = VS_CODE_ERR_FILE_READ;
    vs_esp_storage_ctx_t *ctx = (vs_esp_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(out_data, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->dir, VS_CODE_ERR_INCORRECT_PARAMETER);

#if VS_FIO_PROFILE_READ
    VS_PROFILE_START;
#endif

    if (vs_files_read(ctx->dir, (char *)file, offset, out_data, data_sz, &read_sz) && read_sz == data_sz) {
        res = VS_CODE_OK;
    }

#if VS_FIO_PROFILE_READ
    VS_PROFILE_END_IN_MS("Read");
#endif

    return res;
}

/*******************************************************************************/
static ssize_t
_esp_storage_file_size_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_esp_storage_ctx_t *ctx = (vs_esp_storage_ctx_t *)storage_ctx;
    ssize_t res;

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->dir, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_RET(sizeof(vs_storage_element_id_t) > strlen(ctx->dir) + 1,
              VS_CODE_ERR_INCORRECT_PARAMETER,
              "File name too long");
    uint32_t len = sizeof(vs_storage_element_id_t) - strlen(ctx->dir) - 1;

    uint8_t file[len];
    VS_IOT_MEMSET(file, 0, len);
    vs_files_create_filename(id, file, len);

#if VS_FIO_PROFILE_GETLEN
    VS_PROFILE_START;
#endif

    res = vs_files_get_len(ctx->dir, (char *)file);

#if VS_FIO_PROFILE_GETLEN
    VS_PROFILE_END_IN_MS("Get file len");
#endif

    return res;
}

/******************************************************************************/
static vs_status_e
_esp_storage_del_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_esp_storage_ctx_t *ctx = (vs_esp_storage_ctx_t *)storage_ctx;
    vs_status_e res;
    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->dir, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_RET(sizeof(vs_storage_element_id_t) > strlen(ctx->dir) + 1,
              VS_CODE_ERR_INCORRECT_PARAMETER,
              "File name too long");
    uint32_t len = sizeof(vs_storage_element_id_t) - strlen(ctx->dir) - 1;

    uint8_t file[len];
    VS_IOT_MEMSET(file, 0, len);
    vs_files_create_filename(id, file, len);

#if VS_FIO_PROFILE_REMOVE
    VS_PROFILE_START;
#endif

    res = vs_files_remove(ctx->dir, (char *)file) ? VS_CODE_OK : VS_CODE_ERR_FILE_DELETE;

#if VS_FIO_PROFILE_REMOVE
    VS_PROFILE_END_IN_MS("Remove");
#endif

    return res;
}

/******************************************************************************/
vs_storage_impl_func_t
vs_esp_storage_impl_func(void) {
    vs_storage_impl_func_t impl;

    memset(&impl, 0, sizeof(impl));

    impl.size = _esp_storage_file_size_hal;
    impl.deinit = _esp_storage_deinit_hal;
    impl.open = _esp_storage_open_hal;
    impl.sync = _esp_storage_sync_hal;
    impl.close = _esp_storage_close_hal;
    impl.save = _esp_storage_save_hal;
    impl.load = _esp_storage_load_hal;
    impl.del = _esp_storage_del_hal;

    return impl;
}

/******************************************************************************/
