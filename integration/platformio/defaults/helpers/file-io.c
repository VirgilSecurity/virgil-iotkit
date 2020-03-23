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

#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include <helpers/kdf2.h>
#include <helpers/file-io.h>
#include <sdkconfig.h>

#define UNIX_CALL(OPERATION)                                                                                           \
    do {                                                                                                               \
        if (OPERATION) {                                                                                               \
            VS_LOG_ERROR("Unix call " #OPERATION " error. errno = %d (%s)", errno, strerror(errno));                   \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

/******************************************************************************/
static bool
_check_fio_and_path(const char *folder, const char *file_name, char file_path[CONFIG_SPIFFS_OBJ_NAME_LEN]) {
    int res = VS_IOT_SNPRINTF(file_path, CONFIG_SPIFFS_OBJ_NAME_LEN, "%s/%s", folder, file_name);

    if (res < 0 || res >= CONFIG_SPIFFS_OBJ_NAME_LEN) {
        return false;
    }

    return true;
}

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
void
vs_files_create_filename(const vs_storage_element_id_t id, uint8_t *filename, uint32_t out_len) {
    VS_IOT_ASSERT(out_len);
    VS_IOT_ASSERT(filename);

    uint8_t buf[(out_len - 1) / 2];
    vs_mbedtls_kdf2(
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), id, sizeof(vs_storage_element_id_t), buf, sizeof(buf));
    _data_to_hex(buf, sizeof(buf), filename, &out_len);
}

/******************************************************************************/
bool
vs_files_sync(const char *folder, const char *file_name) {
    bool res = true;
    char file_path[CONFIG_SPIFFS_OBJ_NAME_LEN];

    CHECK_NOT_ZERO(folder);
    CHECK_NOT_ZERO(file_name);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

terminate:
    return res;
}

/******************************************************************************/
static int
_mkdir_recursive(const char *dir) {
    char tmp[CONFIG_SPIFFS_OBJ_NAME_LEN];
    char *p = NULL;
    size_t len;

    VS_IOT_SNPRINTF(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            VS_LOG_DEBUG("Creating directory [%s]", tmp);

            if (mkdir(tmp, 0777) && errno != EEXIST) {
                VS_LOG_ERROR("mkdir call for [%s] path has not been successful. errno = %d (%s)",
                             tmp,
                             errno,
                             strerror(errno));
                return -1;
            }
            *p = '/';
        }
    }

    VS_LOG_DEBUG("Creating directory [%s]", tmp);

    if (mkdir(tmp, 0777) && errno != EEXIST) {
        VS_LOG_ERROR("mkdir call for [%s] path has not been successful. errno = %d (%s)", tmp, errno, strerror(errno));
        return -1;
    }
    return 0;
}

/******************************************************************************/
bool
vs_files_create_subdir(const char *folder) {
    CHECK_NOT_ZERO_RET(folder && folder[0], false);

    return 0 == _mkdir_recursive(folder);
}

/******************************************************************************/
ssize_t
vs_files_get_len(const char *folder, const char *file_name) {

    ssize_t res = -1;
    char file_path[CONFIG_SPIFFS_OBJ_NAME_LEN];
    FILE *fp = NULL;

    CHECK_NOT_ZERO_RET(folder, -1);
    CHECK_NOT_ZERO_RET(file_name, -1);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

    fp = fopen(file_path, "rb");

    if (fp) {
        UNIX_CALL(fseek(fp, 0, SEEK_END));
        res = ftell(fp);

        if (res <= 0) {
            VS_LOG_ERROR("Unable to prepare file [%s] to get len. errno = %d (%s)", file_path, errno, strerror(errno));
            res = -1;
            goto terminate;
        }
    } else {
        VS_LOG_WARNING("Unable to open file [%s] to get len. errno = %d (%s)", file_path, errno, strerror(errno));
    }

terminate:
    if (fp) {
        fclose(fp);
    }

    return res;
}


/******************************************************************************/
bool
vs_files_write(const char *folder, const char *file_name, uint32_t offset, const void *data, size_t data_sz) {
    char file_path[CONFIG_SPIFFS_OBJ_NAME_LEN];
    FILE *fp = NULL;
    bool res = false;
    uint8_t *buf = NULL;
    uint32_t new_file_sz;

    CHECK_NOT_ZERO_RET(folder, false);
    CHECK_NOT_ZERO_RET(file_name, false);
    CHECK_NOT_ZERO_RET(data, false);
    CHECK_NOT_ZERO_RET(data_sz, false);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

    fp = fopen(file_path, "rb");
    if (fp) {
        ssize_t f_sz;
        UNIX_CALL(fseek(fp, 0, SEEK_END));
        f_sz = ftell(fp);
        rewind(fp);

        if (f_sz <= 0) {
            VS_LOG_ERROR("Unable to prepare file [%s] to write. errno = %d (%s)", file_path, errno, strerror(errno));
            res = false;
            goto terminate;
        }

        new_file_sz = f_sz > offset + data_sz ? f_sz : offset + data_sz;
        buf = VS_IOT_MALLOC(new_file_sz);
        CHECK_NOT_ZERO(buf);
        VS_IOT_MEMSET(buf, 0xFF, new_file_sz);

        if (1 != fread((void *)buf, f_sz, 1, fp)) {
            VS_LOG_ERROR("Unable to prepare file [%s] to write. errno = %d (%s)", file_path, errno, strerror(errno));
            res = false;
            goto terminate;
        }

        fclose(fp);
        VS_IOT_MEMCPY(buf + offset, data, data_sz);
    } else {
        new_file_sz = offset + data_sz;
        buf = VS_IOT_CALLOC(offset + data_sz, 1);
        CHECK_NOT_ZERO(buf);
        VS_IOT_MEMSET(buf, 0xFF, offset);
        VS_IOT_MEMCPY(buf + offset, data, data_sz);
    }

    fp = fopen(file_path, "wb");

    if (fp) {
        if (1 != fwrite(buf, new_file_sz, 1, fp)) {
            VS_LOG_ERROR("Unable to write %d bytes to the file [%s]. errno = %d (%s)",
                         data_sz,
                         file_path,
                         errno,
                         strerror(errno));
            goto terminate;
        }

        VS_LOG_DEBUG("Write file [%s] success, %d bytes", file_path, data_sz);
        res = true;

    } else {
        VS_LOG_ERROR("Unable to open file [%s] to write . errno = %d (%s)", file_path, errno, strerror(errno));
    }

terminate:

    if (fp) {
        fclose(fp);
    }

    VS_IOT_FREE(buf);
    return res;
}

/******************************************************************************/
bool
vs_files_read(const char *folder,
              const char *file_name,
              uint32_t offset,
              uint8_t *data,
              size_t buf_sz,
              size_t *read_sz) {
    char file_path[CONFIG_SPIFFS_OBJ_NAME_LEN];
    FILE *fp = NULL;
    bool res = false;
    int64_t max_avail_sz;

    CHECK_NOT_ZERO_RET(folder, false);
    CHECK_NOT_ZERO_RET(file_name, false);
    CHECK_NOT_ZERO_RET(data, false);
    CHECK_NOT_ZERO_RET(read_sz, false);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

    // Real read in case of cache is absent
    fp = fopen(file_path, "rb");

    if (fp) {
        UNIX_CALL(fseek(fp, offset, SEEK_END));
        max_avail_sz = ftell(fp) - offset;

        if (max_avail_sz < 0) {
            VS_LOG_ERROR("File [%s] is smaller than offset %u", buf_sz, file_path, offset);
            *read_sz = 0;
            goto terminate;
        }

        UNIX_CALL(fseek(fp, offset, SEEK_SET));

        *read_sz = max_avail_sz < buf_sz ? max_avail_sz : buf_sz;

        if (1 == fread((void *)data, *read_sz, 1, fp)) {
            VS_LOG_DEBUG("Read file [%s] success, %d bytes", file_path, (int)*read_sz);
            res = true;
        } else {
            VS_LOG_ERROR("Unable to read %d bytes from [%s]", *read_sz, file_path);
            *read_sz = 0;
        }

    } else {
        VS_LOG_ERROR("Unable to open file [%s] to read. errno = %d (%s)", file_path, errno, strerror(errno));
    }

terminate:

    if (fp) {
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
bool
vs_files_remove(const char *folder, const char *file_name) {
    char file_path[CONFIG_SPIFFS_OBJ_NAME_LEN];

    if (!folder || !file_name) {
        VS_LOG_ERROR("Zero arguments");
        return false;
    }

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

    VS_LOG_DEBUG("Remove file:[%s]", file_path);

    remove(file_path);

    return true;
}
