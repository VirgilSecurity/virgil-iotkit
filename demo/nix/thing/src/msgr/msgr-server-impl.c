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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <msgr/msgr-server-impl.h>
#include <virgil/iot/protocols/snap.h>

#include "helpers/app-helpers.h"

#define DEVICE_FILENAME_PREFIX "/tmp/SENS_"
static uint8_t device_file_path[sizeof(DEVICE_FILENAME_PREFIX) - 1 + sizeof(struct vs_mac_addr_t) * 2 + 1];

#define UNIX_CALL(OPERATION)                                                                                           \
    do {                                                                                                               \
        if (OPERATION) {                                                                                               \
            VS_LOG_ERROR("Unix call " #OPERATION " error. errno = %d (%s)", errno, strerror(errno));                   \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

/******************************************************************************/
static vs_status_e
_snap_msgr_get_data_cb(uint8_t *data, uint32_t buf_sz, uint32_t *data_sz) {
    vs_status_e ret_code = VS_CODE_OK;
    vs_mac_addr_t mac_addr;
    uint32_t hex_len = sizeof(struct vs_mac_addr_t) * 2 + 1;
    FILE *fp = NULL;

    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    memset(data, 0, buf_sz);
    *data_sz = 0;

    if (0 == device_file_path[0]) {
        STATUS_CHECK_RET(vs_snap_mac_addr(NULL, &mac_addr), "Can't get mac addr");

        CHECK_RET(vs_app_data_to_hex(mac_addr.bytes,
                                     sizeof(vs_mac_addr_t),
                                     device_file_path + strlen(DEVICE_FILENAME_PREFIX),
                                     &hex_len),
                  VS_CODE_ERR_INCORRECT_ARGUMENT,
                  "Error while convert to env var name");
        memcpy(device_file_path, DEVICE_FILENAME_PREFIX, strlen(DEVICE_FILENAME_PREFIX)); //-V575
        VS_LOG_DEBUG("Emulated device file path : %s", device_file_path);
    }

    fp = fopen((char *)device_file_path, "rb");

    if (fp) {
        ssize_t f_size = -1;
        ret_code = VS_CODE_ERR_FILE_READ;

        UNIX_CALL(fseek(fp, 0, SEEK_END));
        f_size = ftell(fp);

        if (0 == f_size) {
            goto terminate;
        }

        CHECK(f_size > 0,
              "Unable to prepare file %s to read. errno = %d (%s)",
              device_file_path,
              errno,
              strerror(errno));

        CHECK(f_size < buf_sz, "Input buffer is too small");

        UNIX_CALL(fseek(fp, 0, SEEK_SET));

        CHECK(1 == fread((void *)data, f_size, 1, fp),
              "Unable to read %d bytes from %s, errno = %d (%s)",
              f_size,
              device_file_path,
              errno,
              strerror(errno));

        *data_sz = f_size + 1;
        VS_LOG_DEBUG("Remote device variable value : %s", (char *)data);

        ret_code = VS_CODE_OK;
    }

terminate:
    if (fp) {
        fclose(fp);
    }

    return ret_code;
}

/******************************************************************************/
static vs_status_e
_snap_msgr_set_data_cb(uint8_t *data, uint32_t data_sz) {
    return VS_CODE_OK;
}

/******************************************************************************/
vs_snap_msgr_server_service_t
vs_snap_msgr_server_impl(void) {
    vs_snap_msgr_server_service_t msgr_server_cb = {_snap_msgr_get_data_cb, _snap_msgr_set_data_cb};
    return msgr_server_cb;
}

/******************************************************************************/
