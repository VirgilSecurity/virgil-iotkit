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

#include <stdio.h>

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/status_code/status_code.h>

#include <global-hal.h>

#include "sdk-impl/storage/storage-nix-impl.h"

#define VS_FIO_PROFILE_WRITE 0
#define VS_FIO_PROFILE_GETLEN 0
#define VS_FIO_PROFILE_READ 0
#define VS_FIO_PROFILE_SYNC 0

#if VS_FIO_PROFILE_WRITE || VS_FIO_PROFILE_READ || VS_FIO_PROFILE_SYNC || VS_FIO_PROFILE_GETLEN
#include <sys/time.h>
static long long _processing_time = 0;
static long _calls_counter = 0;

static long long
current_timestamp() {
    struct timeval te;
    gettimeofday(&te, NULL);                            // get current time
    long long _us = te.tv_sec * 1000000LL + te.tv_usec; // calculate us
    return _us;
}

#endif

typedef struct {
    char *dir;

} vs_nix_storage_ctx_t;

/******************************************************************************/
static void
_data_to_hex(const uint8_t *_data, uint32_t _len, uint8_t *_out_data, uint32_t *_in_out_len) {
    const uint8_t hex_str[] = "0123456789abcdef";

    VS_IOT_ASSERT(_in_out_len);
    VS_IOT_ASSERT(_data);
    VS_IOT_ASSERT(_out_data);
    VS_IOT_ASSERT(*_in_out_len >= _len * 2 + 1);

    *_in_out_len = _len * 2 + 1;
    _out_data[*_in_out_len - 1] = 0;
    size_t i;

    for (i = 0; i < _len; i++) {
        _out_data[i * 2 + 0] = hex_str[(_data[i] >> 4) & 0x0F];
        _out_data[i * 2 + 1] = hex_str[(_data[i]) & 0x0F];
    }
}

/******************************************************************************/
vs_storage_impl_data_ctx_t
vs_nix_storage_impl_data_init(const char *relative_dir) {
    vs_nix_storage_ctx_t *ctx = NULL;

    CHECK_NOT_ZERO_RET(relative_dir, NULL);

    ctx = VS_IOT_CALLOC(1, sizeof(vs_nix_storage_ctx_t));
    CHECK_NOT_ZERO_RET(ctx, NULL);

    ctx->dir = (char *)VS_IOT_CALLOC(1, strlen(relative_dir) + 1);
    if (NULL == ctx->dir) {
        VS_LOG_ERROR("Can't allocate memory");
        VS_IOT_FREE(ctx);
        return NULL;
    }

    VS_IOT_STRCPY(ctx->dir, relative_dir);

    // Create path
    vs_files_create_subdir(relative_dir);

    return ctx;
}

/******************************************************************************/
static vs_status_e
vs_nix_storage_deinit_hal(vs_storage_impl_data_ctx_t storage_ctx) {
    vs_nix_storage_ctx_t *ctx = (vs_nix_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->dir, VS_CODE_ERR_INCORRECT_PARAMETER);

    VS_IOT_FREE(ctx->dir);
    VS_IOT_FREE(ctx);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_storage_file_t
vs_nix_storage_open_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_nix_storage_ctx_t *ctx = (vs_nix_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(id, NULL);
    CHECK_NOT_ZERO_RET(storage_ctx, NULL);
    CHECK_NOT_ZERO_RET(ctx->dir, NULL);

    uint32_t len = sizeof(vs_storage_element_id_t) * 2 + 1;
    uint8_t *file = (uint8_t *)VS_IOT_CALLOC(1, len);
    CHECK_NOT_ZERO_RET(file, NULL);

    _data_to_hex(id, sizeof(vs_storage_element_id_t), file, &len);

    return file;
}

/******************************************************************************/
vs_status_e static vs_nix_storage_sync_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_file_t file) {
    vs_status_e res = VS_CODE_ERR_FILE;

    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    vs_nix_storage_ctx_t *ctx = (vs_nix_storage_ctx_t *)storage_ctx;

#if VS_FIO_PROFILE_SYNC
    long long t;
    long long dt;
    _calls_counter++;
    t = current_timestamp();
#endif

    if (vs_files_sync(ctx->dir, (char *)file)) {
        res = VS_CODE_OK;
    }
#if VS_FIO_PROFILE_SYNC
    dt = current_timestamp() - t;
    _processing_time += dt;
    VS_LOG_INFO("[Sync]. Time op = %lld us Total time: %lld us Calls: %ld", dt, _processing_time, _calls_counter);
#endif
    return res;
}

/******************************************************************************/
static vs_status_e
vs_nix_storage_close_hal(const vs_storage_impl_data_ctx_t storage_ctx, vs_storage_file_t file) {
    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_INCORRECT_PARAMETER);

    VS_IOT_FREE(file);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
vs_nix_storage_save_hal(const vs_storage_impl_data_ctx_t storage_ctx,
                        const vs_storage_file_t file,
                        size_t offset,
                        const uint8_t *data,
                        size_t data_sz) {
    vs_status_e res = VS_CODE_ERR_FILE_WRITE;

    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_NULLPTR_ARGUMENT);
    vs_nix_storage_ctx_t *ctx = (vs_nix_storage_ctx_t *)storage_ctx;
#if VS_FIO_PROFILE_WRITE
    long long t;
    long long dt;
    _calls_counter++;
    t = current_timestamp();
#endif

    if (vs_files_write(ctx->dir, (char *)file, offset, data, data_sz)) {
        res = VS_CODE_OK;
    }
#if VS_FIO_PROFILE_WRITE
    dt = current_timestamp() - t;
    _processing_time += dt;
    VS_LOG_INFO("[Write]. Time op = %lld us Total time: %lld us Calls: %ld", dt, _processing_time, _calls_counter);
#endif
    return res;
}

/******************************************************************************/
static vs_status_e
vs_nix_storage_load_hal(const vs_storage_impl_data_ctx_t storage_ctx,
                        const vs_storage_file_t file,
                        size_t offset,
                        uint8_t *out_data,
                        size_t data_sz) {
    size_t read_sz;
    vs_status_e res = VS_CODE_ERR_FILE_READ;
    vs_nix_storage_ctx_t *ctx = (vs_nix_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(out_data, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(file, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->dir, VS_CODE_ERR_INCORRECT_PARAMETER);

#if VS_FIO_PROFILE_READ
    long long t;
    long long dt;
    _calls_counter++;
    t = current_timestamp();
#endif
    if (vs_files_read(ctx->dir, (char *)file, offset, out_data, data_sz, &read_sz) && read_sz == data_sz) {
        res = VS_CODE_OK;
    }

#if VS_FIO_PROFILE_READ
    dt = current_timestamp() - t;
    _processing_time += dt;
    VS_LOG_INFO("[Read]. Time op = %lld us Total time: %lld us Calls: %ld", dt, _processing_time, _calls_counter);
#endif
    return res;
}

/*******************************************************************************/
static ssize_t
vs_nix_storage_file_size_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_nix_storage_ctx_t *ctx = (vs_nix_storage_ctx_t *)storage_ctx;
    ssize_t res;
    uint32_t len = sizeof(vs_storage_element_id_t) * 2 + 1;
    uint8_t file[len];

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->dir, VS_CODE_ERR_INCORRECT_PARAMETER);

    _data_to_hex(id, sizeof(vs_storage_element_id_t), file, &len);

#if VS_FIO_PROFILE_GETLEN
    long long t;
    long long dt;
    _calls_counter++;
    t = current_timestamp();
#endif
    res = vs_files_get_len(ctx->dir, (char *)file);
#if VS_FIO_PROFILE_GETLEN
    dt = current_timestamp() - t;
    _processing_time += dt;
    VS_LOG_INFO(
            "[Get file len]. Time op = %lld us Total time: %lld us Calls: %ld", dt, _processing_time, _calls_counter);
#endif
    return res;
}

/******************************************************************************/
static vs_status_e
vs_nix_storage_del_hal(const vs_storage_impl_data_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    vs_nix_storage_ctx_t *ctx = (vs_nix_storage_ctx_t *)storage_ctx;

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(ctx->dir, VS_CODE_ERR_INCORRECT_PARAMETER);

    uint32_t len = sizeof(vs_storage_element_id_t) * 2 + 1;
    uint8_t file[len];

    _data_to_hex(id, sizeof(vs_storage_element_id_t), file, &len);

    return vs_files_remove(ctx->dir, (char *)file) ? VS_CODE_OK : VS_CODE_ERR_FILE_DELETE;
}

/******************************************************************************/
vs_storage_impl_func_t
vs_nix_storage_impl_func(void) {
    vs_storage_impl_func_t impl;

    memset(&impl, 0, sizeof(impl));

    impl.size = vs_nix_storage_file_size_hal;
    impl.deinit = vs_nix_storage_deinit_hal;
    impl.open = vs_nix_storage_open_hal;
    impl.sync = vs_nix_storage_sync_hal;
    impl.close = vs_nix_storage_close_hal;
    impl.save = vs_nix_storage_save_hal;
    impl.load = vs_nix_storage_load_hal;
    impl.del = vs_nix_storage_del_hal;

    return impl;
}

/******************************************************************************/
