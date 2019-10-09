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
#include <virgil/iot/logger/helpers.h>

#include <nix-file-io.h>
#include <nix-crypto-impl.h>

static char base_dir[FILENAME_MAX] = {0};
static char *main_storage_dir = 0;
static const char *tl_dir = "trust_list";
static const char *firmware_dir = "firmware";
static const char *secbox_dir = "secbox";
static bool initialized = false;
static uint8_t mac[6];

#define VS_IO_BUF_SZ (2048 * 1024)
static char file_io_buffer[VS_IO_BUF_SZ];

#define CHECK_SNPRINTF(BUF, FORMAT, ...)                                                                               \
    do {                                                                                                               \
        int snprintf_res;                                                                                              \
        if ((snprintf_res = snprintf((BUF), sizeof(BUF), (FORMAT), ##__VA_ARGS__)) <= 0) {                             \
            VS_LOG_ERROR("snprintf error result %d. errno = %d (%s)", snprintf_res, errno, strerror(errno));           \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

#define UNIX_CALL(OPERATION)                                                                                           \
    do {                                                                                                               \
        if (OPERATION) {                                                                                               \
            VS_LOG_ERROR("Unix call " #OPERATION " error. errno = %d (%s)", errno, strerror(errno));                   \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

/******************************************************************************/

void
vs_hal_files_set_mac(uint8_t mac_addr[6]) {
    VS_IOT_MEMCPY(mac, mac_addr, 6);
}

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

/********************************************************************************/
const char *
vs_nix_get_secbox_dir() {
    return secbox_dir;
}

/******************************************************************************/
static bool
_init_file_io(void) {
    char tmp[FILENAME_MAX];

    vs_nix_get_keystorage_base_dir(base_dir);

    VS_LOG_DEBUG("Base directory for slots : %s", base_dir);

    CHECK_SNPRINTF(tmp, "%s/%s", base_dir, vs_nix_get_slots_dir());

    if (-1 == _mkdir_recursive(tmp)) {
        goto terminate;
    }

    CHECK_SNPRINTF(tmp, "%s/%s", base_dir, tl_dir);

    if (-1 == _mkdir_recursive(tmp)) {
        goto terminate;
    }

    CHECK_SNPRINTF(tmp, "%s/%s", base_dir, firmware_dir);

    if (-1 == _mkdir_recursive(tmp)) {
        goto terminate;
    }

    CHECK_SNPRINTF(tmp, "%s/%s", base_dir, secbox_dir);

    if (-1 == _mkdir_recursive(tmp)) {
        goto terminate;
    }

    initialized = true;

terminate:

    return initialized;
}

/******************************************************************************/
static bool
_check_fio_and_path(const char *folder, const char *file_name, char file_path[FILENAME_MAX]) {
    if (!initialized && !_init_file_io()) {
        VS_LOG_ERROR("Unable to initialize file I/O operations");
        return false;
    }

    if (VS_IOT_SNPRINTF(file_path, FILENAME_MAX, "%s/%s", base_dir, folder) < 0) {
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
vs_nix_get_file_len(const char *folder, const char *file_name) {

    ssize_t res = -1;
    char file_path[FILENAME_MAX];
    FILE *fp = NULL;

    NOT_ZERO(folder);
    NOT_ZERO(file_name);

    if (!initialized && !_init_file_io()) {
        VS_LOG_ERROR("Unable to initialize file I/O operations");
        return 0;
    }

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return 0;
    }

    fp = fopen(file_path, "rb");

    if (fp) {
        UNIX_CALL(fseek(fp, 0, SEEK_END));
        res = ftell(fp);

        if (res <= 0) {
            VS_LOG_ERROR("Unable to prepare file %s to write. errno = %d (%s)", file_path, errno, strerror(errno));
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
vs_nix_sync_file(const char *folder, const char *file_name) {
    bool res = true;
    char file_path[FILENAME_MAX];

    NOT_ZERO(folder);
    NOT_ZERO(file_name);

    if (!initialized && !_init_file_io()) {
        VS_LOG_ERROR("Unable to initialize file I/O operations");
        return false;
    }

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

terminate:
    return res;
}

/******************************************************************************/
bool
vs_nix_write_file_data(const char *folder, const char *file_name, uint32_t offset, const void *data, size_t data_sz) {
    char file_path[FILENAME_MAX];
    FILE *fp = NULL;
    bool res = false;
    uint8_t *buf = NULL;
    uint32_t new_file_sz;

    NOT_ZERO(folder);
    NOT_ZERO(file_name);
    NOT_ZERO(data);
    NOT_ZERO(data_sz);

    if (!initialized && !_init_file_io()) {
        VS_LOG_ERROR("Unable to initialize file I/O operations");
        return false;
    }

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
                VS_LOG_ERROR("Unable to prepare file %s to write. errno = %d (%s)", file_path, errno, strerror(errno));
                res = false;
                goto terminate;
            }

            new_file_sz = f_sz > offset + data_sz ? f_sz : offset + data_sz;
            buf = VS_IOT_MALLOC(new_file_sz);
            NOT_ZERO(buf);
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
            NOT_ZERO(buf);
            VS_IOT_MEMSET(buf, 0xFF, offset);
            VS_IOT_MEMCPY(buf + offset, data, data_sz);
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
vs_nix_read_file_data(const char *folder,
                      const char *file_name,
                      uint32_t offset,
                      uint8_t *data,
                      size_t buf_sz,
                      size_t *read_sz) {
    char file_path[FILENAME_MAX];
    FILE *fp = NULL;
    bool res = false;
    int64_t max_avail_sz;

    NOT_ZERO(folder);
    NOT_ZERO(file_name);
    NOT_ZERO(data);
    NOT_ZERO(read_sz);

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        goto terminate;
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

        VS_LOG_DEBUG("Read file '%s', %d bytes", file_path, (int)*read_sz);

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
vs_nix_remove_file_data(const char *folder, const char *file_name) {
    char file_path[FILENAME_MAX];

    if (!folder || !file_name) {
        VS_LOG_ERROR("Zero arguments");
        return false;
    }

    if (!_check_fio_and_path(folder, file_name, file_path)) {
        return false;
    }

    remove(file_path);

    return true;
}

/******************************************************************************/
bool
vs_nix_get_keystorage_base_dir(char *dir) {
    struct passwd *pwd = NULL;

    assert(main_storage_dir);
    if (!main_storage_dir) {
        return false;
    }

    pwd = getpwuid(getuid());

    if (VS_IOT_SNPRINTF(dir,
                        FILENAME_MAX,
                        "%s/%s/%s/%x:%x:%x:%x:%x:%x",
                        pwd->pw_dir,
                        "keystorage",
                        main_storage_dir,
                        mac[0],
                        mac[1],
                        mac[2],
                        mac[3],
                        mac[4],
                        mac[5]) <= 0) {
        return false;
    }
    return true;
}

#undef UNIX_CALL
#undef CHECK_SNPRINTF

/********************************************************************************/
const char *
vs_nix_get_trust_list_dir() {
    return tl_dir;
}

/********************************************************************************/
const char *
vs_nix_get_firmware_dir() {
    return firmware_dir;
}

/******************************************************************************/
void
vs_hal_files_set_dir(const char *dir_name) {
    assert(dir_name && dir_name[0]);

    if (main_storage_dir) {
        free(main_storage_dir);
        main_storage_dir = 0;
    }

    main_storage_dir = strdup(dir_name);
}
/******************************************************************************/
