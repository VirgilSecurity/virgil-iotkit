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

#include "nvs.h"

#include <defaults/storage/storage-esp-impl.h>
#include <sdkconfig.h>

#include <helpers/file-io.h>

#if VS_NVS_PROFILE_WRITE || VS_NVS_PROFILE_READ || VS_NVS_PROFILE_SYNC || VS_NVS_PROFILE_GETLEN || VS_NVS_PROFILE_REMOVE
#include <helpers/profiling.h>
#else
#define VS_PROFILE_START
#define VS_PROFILE_END_IN_MS(DESC)
#endif

#define NVS_MAX_KEY_NAME_LEN (16)
static const char *_nvs_slots_namespace = "NVS_SLOTS";

typedef struct {
    char *namespace;
    nvs_handle handle;
} vs_nvs_storage_ctx_t;

vs_storage_impl_data_ctx_t
_nvs_storage_impl_data_init(const char *namespace);

static vs_status_e
_nvs_storage_deinit_hal(vs_storage_impl_data_ctx_t storage_ctx);

static vs_storage_file_t
_nvs_storage_open_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id);

static vs_status_e
_nvs_storage_close_hal(const vs_storage_impl_data_ctx_t storage_ctx, vs_storage_file_t file);

static vs_status_e
_nvs_storage_save_hal(const vs_storage_impl_data_ctx_t storage_ctx,
                      const vs_storage_file_t file,
                      size_t offset,
                      const uint8_t *data,
                      size_t data_sz);
static vs_status_e
_nvs_storage_load_hal(const vs_storage_impl_data_ctx_t storage_ctx,
                      const vs_storage_file_t file,
                      size_t offset,
                      uint8_t *out_data,
                      size_t data_sz);

static vs_status_e
_nvs_storage_sync_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_file_t file);

static ssize_t
_nvs_storage_file_size_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id);

static vs_status_e
_nvs_storage_del_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id);

vs_storage_impl_func_t
_nvs_storage_impl_func(void);

/******************************************************************************/
vs_status_e
vs_app_nvs_storage_init_impl(vs_storage_op_ctx_t *storage_impl, const char *namespace, size_t file_size_max) {
    CHECK_NOT_ZERO_RET(storage_impl, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(namespace, VS_CODE_ERR_INCORRECT_ARGUMENT);

    memset(storage_impl, 0, sizeof(*storage_impl));

    // Prepare TL storage
    storage_impl->impl_func = _nvs_storage_impl_func();
    storage_impl->impl_data = _nvs_storage_impl_data_init(namespace);
    storage_impl->file_sz_limit = file_size_max;

    return VS_CODE_OK;
}

/******************************************************************************/
const char *
vs_app_nvs_slots_namespace(void) {
    return _nvs_slots_namespace;
}

/******************************************************************************/
vs_storage_impl_data_ctx_t
_nvs_storage_impl_data_init(const char *namespace) {
    vs_nvs_storage_ctx_t *ctx = NULL;

    CHECK_NOT_ZERO_RET(namespace, NULL);

    ctx = VS_IOT_CALLOC(1, sizeof(vs_nvs_storage_ctx_t));
    CHECK_NOT_ZERO_RET(ctx, NULL);

    ctx->namespace = (char *)VS_IOT_CALLOC(1, strlen(namespace) + 1);

    if (NULL == ctx->namespace) {
        VS_LOG_ERROR("Can't allocate memory");
        VS_IOT_FREE(ctx);
        return NULL;
    }

    VS_IOT_STRCPY(ctx->namespace, namespace);
    VS_LOG_DEBUG("NVS namespace [%s]", ctx->namespace);

    return ctx;
}

/******************************************************************************/
vs_storage_impl_func_t
_nvs_storage_impl_func(void) {
    vs_storage_impl_func_t impl;

    memset(&impl, 0, sizeof(impl));

    impl.size = _nvs_storage_file_size_hal;
    impl.deinit = _nvs_storage_deinit_hal;
    impl.open = _nvs_storage_open_hal;
    impl.sync = _nvs_storage_sync_hal;
    impl.close = _nvs_storage_close_hal;
    impl.save = _nvs_storage_save_hal;
    impl.load = _nvs_storage_load_hal;
    impl.del = _nvs_storage_del_hal;

    return impl;
}

/******************************************************************************/
static vs_status_e
_nvs_storage_deinit_hal(vs_storage_impl_data_ctx_t storage_ctx) {
    vs_nvs_storage_ctx_t *ctx = (vs_nvs_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->namespace, VS_CODE_ERR_INCORRECT_PARAMETER);

    VS_IOT_FREE(ctx->namespace);
    VS_IOT_FREE(ctx);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_storage_file_t
_nvs_storage_open_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_nvs_storage_ctx_t *ctx = (vs_nvs_storage_ctx_t *)storage_ctx;
    uint32_t len = NVS_MAX_KEY_NAME_LEN;

    CHECK_NOT_ZERO_RET(id, NULL);
    CHECK_NOT_ZERO_RET(storage_ctx, NULL);
    CHECK_NOT_ZERO_RET(ctx->namespace, NULL);

    uint8_t *file = (uint8_t *)VS_IOT_CALLOC(1, len);
    CHECK_NOT_ZERO_RET(file, NULL);
    vs_files_create_filename(id, file, len);

    if (ESP_OK != nvs_open(ctx->namespace, NVS_READWRITE, &ctx->handle)) {
        VS_LOG_ERROR("Can't open namespace");
        VS_IOT_FREE(file);
        return NULL;
    }

    return file;
}

/******************************************************************************/
static vs_status_e
_nvs_storage_save_hal(const vs_storage_impl_data_ctx_t storage_ctx,
                      const vs_storage_file_t file,
                      size_t offset,
                      const uint8_t *data,
                      size_t data_sz) {

    vs_status_e res = VS_CODE_ERR_FILE_WRITE;
    vs_nvs_storage_ctx_t *ctx = (vs_nvs_storage_ctx_t *)storage_ctx;
    uint8_t *buf = NULL;
    uint32_t new_file_sz;
    esp_err_t err;
    size_t f_sz = 0; // value will default to 0, if not set yet in NVS

    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_NULLPTR_ARGUMENT);

#if VS_NVS_PROFILE_WRITE
    VS_PROFILE_START;
#endif
    err = nvs_get_blob(ctx->handle, (char *)file, NULL, &f_sz);
    CHECK(ESP_OK == err || ESP_ERR_NVS_NOT_FOUND == err, "Can't create required key");

    if (f_sz > 0) {
        new_file_sz = f_sz > offset + data_sz ? f_sz : offset + data_sz;
        buf = VS_IOT_MALLOC(new_file_sz);
        CHECK_NOT_ZERO(buf);
        VS_IOT_MEMSET(buf, 0xFF, new_file_sz);

        err = nvs_get_blob(ctx->handle, (char *)file, buf, &f_sz);
        if (ESP_OK != err) {
            VS_LOG_ERROR("Unable to prepare file [%s] to write. err = %d", (char *)file, err);
            goto terminate;
        }
        VS_IOT_MEMCPY(buf + offset, data, data_sz);

    } else {
        new_file_sz = offset + data_sz;
        buf = VS_IOT_CALLOC(offset + data_sz, 1);
        CHECK_NOT_ZERO(buf);
        VS_IOT_MEMSET(buf, 0xFF, offset);
        VS_IOT_MEMCPY(buf + offset, data, data_sz);
    }

    err = nvs_set_blob(ctx->handle, (char *)file, buf, new_file_sz);
    if (ESP_OK != err) {
        VS_LOG_ERROR("Unable to write %d bytes to the file [%s]. err = %d", (char *)file, err);
        goto terminate;
    }

    VS_LOG_DEBUG("Write file [%s] success, %d bytes", (char *)file, data_sz);
    res = VS_CODE_OK;

terminate:
    VS_IOT_FREE(buf);

#if VS_NVS_PROFILE_WRITE
    VS_PROFILE_END_IN_MS("Save");
#endif

    return res;
}

/******************************************************************************/
static vs_status_e
_nvs_storage_load_hal(const vs_storage_impl_data_ctx_t storage_ctx,
                      const vs_storage_file_t file,
                      size_t offset,
                      uint8_t *out_data,
                      size_t data_sz) {
    vs_status_e res = VS_CODE_ERR_FILE_READ;
    vs_nvs_storage_ctx_t *ctx = (vs_nvs_storage_ctx_t *)storage_ctx;
    uint8_t *buf = NULL;
    size_t f_sz = 0;
    int64_t max_avail_sz;
    esp_err_t err;

    CHECK_NOT_ZERO_RET(out_data, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_INCORRECT_PARAMETER);

#if VS_NVS_PROFILE_READ
    VS_PROFILE_START;
#endif

    err = nvs_get_blob(ctx->handle, (char *)file, NULL, &f_sz);
    CHECK(ESP_OK == err, "Can't find required key");

    if (f_sz > 0) {
        max_avail_sz = f_sz - offset;
        CHECK(max_avail_sz >= 0, "File [%s] is smaller than offset %u", (char *)file, offset);

        buf = VS_IOT_MALLOC(f_sz);
        CHECK_NOT_ZERO(buf);

        err = nvs_get_blob(ctx->handle, (char *)file, buf, &f_sz);
        CHECK(ESP_OK == err, "Unable to prepare file [%s] to read. err = %d", (char *)file, err);

        VS_IOT_MEMCPY(out_data, buf + offset, max_avail_sz < data_sz ? max_avail_sz : data_sz);
        VS_LOG_DEBUG("Read file [%s], offs %d success, %d bytes",
                     (char *)file,
                     offset,
                     max_avail_sz < data_sz ? max_avail_sz : data_sz);

        res = VS_CODE_OK;
    } else {
        VS_LOG_ERROR("File size is zero");
    }

terminate:
    VS_IOT_FREE(buf);

#if VS_NVS_PROFILE_READ
    VS_PROFILE_END_IN_MS("Read");
#endif

    return res;
}

/******************************************************************************/
static vs_status_e
_nvs_storage_sync_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_file_t file) {
    vs_status_e res = VS_CODE_ERR_FILE;
    vs_nvs_storage_ctx_t *ctx = (vs_nvs_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

#if VS_NVS_PROFILE_SYNC
    VS_PROFILE_START;
#endif
    if (ESP_OK == nvs_commit(ctx->handle)) {
        res = VS_CODE_OK;
    }

#if VS_NVS_PROFILE_SYNC
    VS_PROFILE_END_IN_MS("sync");
#endif

    return res;
}

/******************************************************************************/
static vs_status_e
_nvs_storage_close_hal(const vs_storage_impl_data_ctx_t storage_ctx, vs_storage_file_t file) {
    vs_nvs_storage_ctx_t *ctx = (vs_nvs_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);

    VS_IOT_FREE(file);

    nvs_close(ctx->handle);
    ctx->handle = 0;

    return VS_CODE_OK;
}

/******************************************************************************/
static ssize_t
_nvs_storage_file_size_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_nvs_storage_ctx_t *ctx = (vs_nvs_storage_ctx_t *)storage_ctx;
    ssize_t res = -1;

    nvs_handle handle;
    esp_err_t err;

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->namespace, VS_CODE_ERR_INCORRECT_PARAMETER);

    uint32_t len = NVS_MAX_KEY_NAME_LEN;

    uint8_t file[NVS_MAX_KEY_NAME_LEN];
    VS_IOT_MEMSET(file, 0, len);
    vs_files_create_filename(id, file, len);

#if VS_NVS_PROFILE_GETLEN
    VS_PROFILE_START;
#endif
    err = nvs_open(ctx->namespace, NVS_READONLY, &handle);
    CHECK_RET(ESP_OK == err, -1, "Can't open namespace %s", ctx->namespace);

    err = nvs_get_blob(handle, (char *)file, NULL, (size_t *)&res);
    CHECK(ESP_OK == err, "Can't find required key");

terminate:
    nvs_close(handle);

#if VS_NVS_PROFILE_GETLEN
    VS_PROFILE_END_IN_MS("Get file len");
#endif

    return res;
}

/******************************************************************************/
static vs_status_e
_nvs_storage_del_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_nvs_storage_ctx_t *ctx = (vs_nvs_storage_ctx_t *)storage_ctx;
    vs_status_e res = VS_CODE_ERR_FILE_DELETE;
    nvs_handle handle;
    esp_err_t err;

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->namespace, VS_CODE_ERR_INCORRECT_PARAMETER);

    uint32_t len = NVS_MAX_KEY_NAME_LEN;

    uint8_t file[len];
    VS_IOT_MEMSET(file, 0, len);
    vs_files_create_filename(id, file, len);

#if VS_NVS_PROFILE_REMOVE
    VS_PROFILE_START;
#endif

    err = nvs_open(ctx->namespace, NVS_READWRITE, &handle);
    CHECK_RET(ESP_OK == err, res, "Can't open namespace");

    nvs_erase_key(handle, (char *)file);
    res = VS_CODE_OK;

    nvs_close(handle);

#if VS_NVS_PROFILE_REMOVE
    VS_PROFILE_END_IN_MS("Remove");
#endif

    return res;
}

/******************************************************************************/
