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

#include <string.h>
#include <stdio.h>

#include "helpers/app-storage.h"
#include "helpers/file-io.h"
#include "sdk-impl/storage/storage-nix-impl.h"

static const char *_tl_dir = "trust_list";
static const char *_firmware_dir = "firmware";
static const char *_slots_dir = "slots";
static const char *_secbox_dir = "secbox";

/******************************************************************************/
vs_status_e
vs_app_prepare_storage(const char *devices_dir, vs_mac_addr_t device_mac) {
    static char base_dir[FILENAME_MAX] = {0};


    CHECK_NOT_ZERO_RET(devices_dir && devices_dir[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    if (VS_IOT_SNPRINTF(base_dir,
                        FILENAME_MAX,
                        "%s/%x:%x:%x:%x:%x:%x",
                        devices_dir,
                        device_mac.bytes[0],
                        device_mac.bytes[1],
                        device_mac.bytes[2],
                        device_mac.bytes[3],
                        device_mac.bytes[4],
                        device_mac.bytes[5]) <= 0) {
        return VS_CODE_ERR_TOO_SMALL_BUFFER;
    }

    return vs_files_set_base_dir(base_dir) ? VS_CODE_OK : VS_CODE_ERR_FILE;
}

/******************************************************************************/
vs_status_e
vs_app_storage_init_impl(vs_storage_op_ctx_t *storage_impl, const char *base_dir, size_t file_size_max) {
    CHECK_NOT_ZERO_RET(storage_impl, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(base_dir, VS_CODE_ERR_INCORRECT_ARGUMENT);

    memset(storage_impl, 0, sizeof(*storage_impl));

    // Prepare TL storage
    storage_impl->impl_func = vs_nix_storage_impl_func();
    storage_impl->impl_data = vs_nix_storage_impl_data_init(base_dir);
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
