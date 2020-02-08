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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>

#include <stdlib-config.h>
#include <global-hal.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <helpers/file-cache.h>

static char _base_dir[FILENAME_MAX] = {0};

#define VS_IO_BUF_SZ (2048 * 1024)
static char file_io_buffer[VS_IO_BUF_SZ];

#define UNIX_CALL(OPERATION)                                                                                           \
    do {                                                                                                               \
        if (OPERATION) {                                                                                               \
            VS_LOG_ERROR("Unix call " #OPERATION " error. errno = %d (%s)", errno, strerror(errno));                   \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

/******************************************************************************/
static int
_mkdir_recursive(const char *dir) {
    char tmp[FILENAME_MAX];
    char *p = NULL;
    size_t len;

    VS_IOT_SNPRINTF(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, S_IRWXU | S_IRWXG | S_IRWXO) && errno != EEXIST) {
                VS_LOG_ERROR(
                        "mkdir call for %s path has not been successful. errno = %d (%s)", tmp, errno, strerror(errno));
                return -1;
            }
            *p = '/';
        }
    if (mkdir(tmp, S_IRWXU | S_IRWXG | S_IRWXO) && errno != EEXIST) {
        VS_LOG_ERROR("mkdir call for %s path has not been successful. errno = %d (%s)", tmp, errno, strerror(errno));
        return -1;
    }
    return 0;
}

/******************************************************************************/
bool
vs_files_create_subdir(const char *folder) {
    static char tmp[FILENAME_MAX];

    CHECK_NOT_ZERO(folder && folder[0]);

    int res = snprintf(tmp, sizeof(tmp), "%s/%s", _base_dir, folder);
    CHECK(res > 0 && res <= FILENAME_MAX, "Error create path");

    return 0 == _mkdir_recursive(tmp);

terminate:

    return false;
}

/******************************************************************************/
static bool
_check_fio_and_path(const char *folder, const char *file_name, char file_path[FILENAME_MAX]) {
    if (VS_IOT_SNPRINTF(file_path, FILENAME_MAX, "%s/%s", _base_dir, folder) < 0) {
        return false;
    }

    if ((strlen(file_path) + strlen(file_name) + 1) >= FILENAME_MAX) {
        return false;
    }

    strcat(file_path, "/");
    strcat(file_path, file_name);

    return true;
}

/******************************************************************************/
ssize_t
vs_files_get_len(const char *folder, const char *file_name) {

    ssize_t res = -1;
    char file_path[FILENAME_MAX];
    FILE *fp = NULL;

    CHECK_NOT_ZERO(folder);
    CHECK_NOT_ZERO(file_name);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return 0;
    }

    // Cached read
    if (0 == vs_file_cache_open(file_path)) {
        res = vs_file_cache_get_len(file_path);
        if (res > 0) {
            return res;
        }
    }

    fp = fopen(file_path, "rb");

    if (fp) {
        UNIX_CALL(fseek(fp, 0, SEEK_END));
        res = ftell(fp);

        if (res <= 0) {
            VS_LOG_ERROR("Unable to prepare file %s to read. errno = %d (%s)", file_path, errno, strerror(errno));
            res = -1;
            goto terminate;
        }
    } else {
        VS_LOG_WARNING("Unable to open file %s. errno = %d (%s)", file_path, errno, strerror(errno));
    }

terminate:
    if (fp) {
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
bool
vs_files_sync(const char *folder, const char *file_name) {
    bool res = true;
    char file_path[FILENAME_MAX];

    CHECK_NOT_ZERO(folder);
    CHECK_NOT_ZERO(file_name);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

    if (vs_file_cache_is_enabled()) {
        res = (0 == vs_file_cache_sync(file_path));
    }

terminate:
    return res;
}

/******************************************************************************/
bool
vs_files_write(const char *folder, const char *file_name, uint32_t offset, const void *data, size_t data_sz) {
    char file_path[FILENAME_MAX];
    FILE *fp = NULL;
    bool res = false;
    uint8_t *buf = NULL;
    uint32_t new_file_sz;

    CHECK_NOT_ZERO(folder);
    CHECK_NOT_ZERO(file_name);
    CHECK_NOT_ZERO(data);
    CHECK_NOT_ZERO(data_sz);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

    if (0 == vs_file_cache_open(file_path)) { // Cached write
        return (0 == vs_file_cache_write(file_path, offset, data, data_sz)) ? true : false;
    } else { // Real write file if cache is disabled or file not found
        fp = fopen(file_path, "rb");
        if (fp) {
            ssize_t f_sz;
            UNIX_CALL(fseek(fp, 0, SEEK_END));
            f_sz = ftell(fp);
            rewind(fp);

            if (f_sz <= 0) {
                VS_LOG_ERROR("Unable to prepare file %s to write. errno = %d (%s)", file_path, errno, strerror(errno));
                res = false;
                goto terminate;
            }

            new_file_sz = f_sz > offset + data_sz ? f_sz : offset + data_sz;
            buf = VS_IOT_MALLOC(new_file_sz);
            CHECK_NOT_ZERO(buf);
            VS_IOT_MEMSET(buf, 0xFF, new_file_sz);

            if (1 != fread((void *)buf, f_sz, 1, fp)) {
                VS_LOG_ERROR("Unable to prepare file %s to write. errno = %d (%s)", file_path, errno, strerror(errno));
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
    }


    fp = fopen(file_path, "wb");

    if (fp) {

        setvbuf(fp, file_io_buffer, _IOFBF, VS_IO_BUF_SZ);
        if (1 != fwrite(buf, new_file_sz, 1, fp)) {
            VS_LOG_ERROR("Unable to write %d bytes to the file %s. errno = %d (%s)",
                         data_sz,
                         file_path,
                         errno,
                         strerror(errno));
            goto terminate;
        }
        vs_file_cache_create(file_path, buf, new_file_sz);

    } else {
        VS_LOG_ERROR("Unable to open file %s. errno = %d (%s)", file_path, errno, strerror(errno));
    }

    res = true;

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
    char file_path[FILENAME_MAX];
    FILE *fp = NULL;
    bool res = false;
    int64_t max_avail_sz;

    CHECK_NOT_ZERO(folder);
    CHECK_NOT_ZERO(file_name);
    CHECK_NOT_ZERO(data);
    CHECK_NOT_ZERO(read_sz);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        goto terminate;
    }

    // Cached read
    if (0 == vs_file_cache_open(file_path)) {
        if (0 == vs_file_cache_read(file_path, offset, data, buf_sz, read_sz)) {
            return true;
        }
    }

    // Real read in case of cache is absent
    fp = fopen(file_path, "rb");

    if (fp) {
        UNIX_CALL(fseek(fp, offset, SEEK_END));
        max_avail_sz = ftell(fp) - offset;

        if (max_avail_sz < 0) {
            VS_LOG_ERROR("File %s is smaller than offset %u", buf_sz, file_path, offset);
            *read_sz = 0;
            goto terminate;
        }

        UNIX_CALL(fseek(fp, offset, SEEK_SET));

        *read_sz = max_avail_sz < buf_sz ? max_avail_sz : buf_sz;

        if (1 == fread((void *)data, *read_sz, 1, fp)) {
            res = true;
        } else {
            VS_LOG_ERROR("Unable to read %d bytes from %s", *read_sz, file_path);
            *read_sz = 0;
        }

    } else {
        VS_LOG_ERROR("Unable to open file %s. errno = %d (%s)", file_path, errno, strerror(errno));
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
    char file_path[FILENAME_MAX];

    if (!folder || !file_name) {
        VS_LOG_ERROR("Zero arguments");
        return false;
    }

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

    vs_file_cache_close(file_path);

    remove(file_path);

    return true;
}

/******************************************************************************/
bool
vs_files_set_base_dir(const char *base_dir) {
    struct passwd *pwd = NULL;

    assert(base_dir && base_dir[0]);

    pwd = getpwuid(getuid());

    if (VS_IOT_SNPRINTF(_base_dir, FILENAME_MAX, "%s/%s/%s", pwd->pw_dir, "keystorage", base_dir) <= 0) {
        return false;
    }
    return true;
}

/******************************************************************************/
const char *
vs_files_get_base_dir(void) {
    return _base_dir;
}
/******************************************************************************/
