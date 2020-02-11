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

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>

/******************************************************************/
const char *
vs_update_file_version_str(const vs_file_version_t *version, char *opt_buf, size_t buf_sz) {
    static char _buf[VS_UPDATE_DEFAULT_DESC_BUF_SZ];
    char *buf = opt_buf != NULL ? opt_buf : _buf;
    size_t sz = opt_buf != NULL ? buf_sz : sizeof(_buf);

    VS_IOT_ASSERT(sz);

    int res = VS_IOT_SNPRINTF(buf,
                              sz,
                              "ver %u.%u.%u.%u, timestamp %u",
                              version->major,
                              version->minor,
                              version->patch,
                              version->build,
                              version->timestamp);
    if (res <= 0) {
        buf[0] = 0;
    } else if(res > sz) {
        buf[sz - 1] = 0;
    }

    return buf;
}

/******************************************************************/
const char *
vs_update_file_type_str(const vs_update_file_type_t *file_type, char *opt_buf, size_t buf_sz) {
    static char _buf[VS_UPDATE_DEFAULT_DESC_BUF_SZ];
    int res;
    char *buf = opt_buf != NULL ? opt_buf : _buf;
    size_t sz = opt_buf != NULL ? buf_sz : sizeof(_buf);

    uint8_t manufacture_id[sizeof(vs_device_manufacture_id_t) + 1];
    VS_IOT_MEMSET(manufacture_id, 0, sizeof(manufacture_id));
    VS_IOT_MEMCPY(manufacture_id, file_type->info.manufacture_id, sizeof(file_type->info.manufacture_id));

    VS_IOT_ASSERT(sz);

    switch (file_type->type) {
    case VS_UPDATE_FIRMWARE:
        {
            res = VS_IOT_SNPRINTF(buf,
                              sz,
                              "Firmware (\"%s\", \"%c%c%c%c\")",
                              manufacture_id,
                              (char)file_type->info.device_type[0],
                              (char)file_type->info.device_type[1],
                              (char)file_type->info.device_type[2],
                              (char)file_type->info.device_type[3]);

    }
    break;

    case VS_UPDATE_TRUST_LIST:
        res = VS_IOT_SNPRINTF(buf,
                              sz,"Trust List");
        break;
    default:
        if (file_type->type <= VS_UPDATE_USER_FILES) {
            res = VS_IOT_SNPRINTF(buf,
                                  sz,
                                  "User file, type = %u (\"%s\", \"%c%c%c%c\")",
                                  file_type->type,
                                  manufacture_id,
                                  (char)file_type->info.device_type[0],
                                  (char)file_type->info.device_type[1],
                                  (char)file_type->info.device_type[2],
                                  (char)file_type->info.device_type[3]);

        } else {
            res = VS_IOT_SNPRINTF(buf,
                                  sz,"Unknown type");
         }
        break;
    }

    if (res <= 0) {
        buf[0] = 0;
    } else if(res > sz) {
        buf[sz - 1] = 0;
    }

    return buf;
}

/*************************************************************************/
bool
vs_update_equal_file_type(vs_update_file_type_t *file_type, const vs_update_file_type_t *unknown_file_type){
    return file_type->type == unknown_file_type->type &&
            !VS_IOT_MEMCMP(file_type->info.manufacture_id, unknown_file_type->info.manufacture_id, sizeof(unknown_file_type->info.manufacture_id)) &&
            !VS_IOT_MEMCMP(file_type->info.device_type, unknown_file_type->info.device_type, sizeof(unknown_file_type->info.device_type));
}

/******************************************************************************/
vs_status_e
vs_update_compare_version(const vs_file_version_t *update_ver, const vs_file_version_t *current_ver) {
    CHECK_NOT_ZERO_RET(update_ver, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(current_ver, VS_CODE_ERR_NULLPTR_ARGUMENT);
    // Compare version
    if (update_ver->major > current_ver->major) {
        return VS_CODE_OK;
    }

    if (update_ver->major == current_ver->major) {
        if(update_ver->minor > current_ver->minor) {
           return VS_CODE_OK;
        }

        if(update_ver->minor == current_ver->minor) {
            if (update_ver->patch > current_ver->patch) {
                return VS_CODE_OK;
            }

            if (update_ver->patch == current_ver->patch) {
                if (update_ver->build > current_ver->build) {
                    return VS_CODE_OK;
                }
            }
        }
    }
    return VS_CODE_OLD_VERSION;
}

/*************************************************************************/
