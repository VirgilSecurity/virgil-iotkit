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

#include <sys/stat.h>
#include <fts.h>
#include <errno.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/tests/tests.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/vs-soft-secmodule/vs-soft-secmodule.h>
#include <virgil/iot/firmware/firmware.h>
#include <update-config.h>
#include <trust_list-config.h>

#include "helpers/app-helpers.h"
#include "helpers/app-storage.h"
#include "helpers/file-io.h"
#include "sdk-impl/storage/storage-nix-impl.h"
#include "sdk-impl/firmware/firmware-nix-impl.h"

/******************************************************************************/
static int
_recursive_delete(const char *dir) {
    int ret = 0;
    FTS *ftsp = NULL;
    FTSENT *curr;

    // Cast needed (in C) because fts_open() takes a "char * const *", instead
    // of a "const char * const *", which is only allowed in C++. fts_open()
    // does not modify the argument.
    char *files[] = {(char *)dir, NULL};

    // FTS_NOCHDIR  - Avoid changing cwd, which could cause unexpected behavior
    //                in multithreaded programs
    // FTS_PHYSICAL - Don't follow symlinks. Prevents deletion of files outside
    //                of the specified directory
    // FTS_XDEV     - Don't cross filesystem boundaries
    ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
    if (!ftsp) {
        VS_LOG_ERROR("%s: fts_open failed", dir);
        ret = -1;
        goto finish;
    }

    while ((curr = fts_read(ftsp))) {
        switch (curr->fts_info) {
        case FTS_NS:
        case FTS_DNR:
        case FTS_ERR:
            VS_LOG_TRACE("%s: fts_read error: %s", curr->fts_accpath, strerror(curr->fts_errno));
            break;

        case FTS_DC:
        case FTS_DOT:
        case FTS_NSOK:
            // Not reached unless FTS_LOGICAL, FTS_SEEDOT, or FTS_NOSTAT were
            // passed to fts_open()
            break;

        case FTS_D:
            // Do nothing. Need depth-first search, so directories are deleted
            // in FTS_DP
            break;

        case FTS_DP:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
        case FTS_DEFAULT:
            if (remove(curr->fts_accpath) < 0) {
                VS_LOG_ERROR("%s: Failed to remove", curr->fts_path);
                ret = -1;
            }
            break;
        }
    }

finish:
    if (ftsp) {
        fts_close(ftsp);
    }

    return ret;
}

/********************************************************************************/
static void
_remove_keystorage_dir() {
    _recursive_delete(vs_files_get_base_dir());
}

/********************************************************************************/
int
main(int argc, char *argv[]) {
    int res = -1;
    vs_mac_addr_t mac;

    vs_provision_events_t provision_events = {NULL};
    vs_file_version_t ver;

    // Device parameters
    vs_device_manufacture_id_t manufacture_id;
    vs_device_type_t device_type;

    // Implementation variables
    vs_secmodule_impl_t *secmodule_impl = NULL;
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t slots_storage_impl;
    vs_storage_op_ctx_t fw_storage_impl;
    vs_storage_op_ctx_t secbox_storage_impl;


    // Prepare device parameters
    memset(&mac, 0, sizeof(mac));
    vs_app_str_to_bytes(manufacture_id, TEST_MANUFACTURE_ID, sizeof(manufacture_id));
    vs_app_str_to_bytes(device_type, TEST_DEVICE_TYPE, sizeof(device_type));

    vs_logger_init(VS_LOGLEV_DEBUG);

    // Set self path
    vs_firmware_nix_set_info(argv[0], manufacture_id, device_type);

    // Prepare local storage
    STATUS_CHECK(vs_app_prepare_storage("test", mac), "Cannot prepare storage");
    _remove_keystorage_dir();

    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(vs_app_storage_init_impl(&slots_storage_impl, vs_app_slots_dir(), VS_SLOTS_STORAGE_MAX_SIZE),
                 "Cannot create Slots storage");

    // Firmware storage
    STATUS_CHECK(vs_app_storage_init_impl(&fw_storage_impl, vs_app_firmware_dir(), VS_MAX_FIRMWARE_UPDATE_SIZE),
                 "Cannot create Firmware storage");

    // Secbox storage
    STATUS_CHECK(vs_app_storage_init_impl(&secbox_storage_impl, vs_app_secbox_dir(), VS_MAX_FIRMWARE_UPDATE_SIZE),
                 "Cannot create Secbox storage");

    // Soft Security Module
    secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

    // Provision module.
    CHECK(VS_CODE_ERR_NOINIT == vs_provision_init(&tl_storage_impl, secmodule_impl, provision_events),
          "Initialization of provision module must return VS_CODE_ERR_NOINIT code");

    // Firmware module
    STATUS_CHECK(vs_firmware_init(&fw_storage_impl, secmodule_impl, manufacture_id, device_type, &ver),
                 "Unable to initialize Firmware module");

    // Secbox module
    STATUS_CHECK(vs_secbox_init(&secbox_storage_impl, secmodule_impl), "Unable to initialize Secbox module");

    VS_LOG_INFO("[RPI] Start IoT tests");

    res = vs_crypto_test(secmodule_impl);

    res += vs_secbox_test(secmodule_impl);

    res += vs_firmware_test(secmodule_impl);

    res += vs_snap_tests();

    VS_LOG_INFO("[RPI] Finish IoT rpi gateway tests");

terminate:
    // Deinit firmware
    vs_firmware_deinit();

    // Deinit provision
    vs_provision_deinit();

    // Deinit secbox
    vs_secbox_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();

    return res;
}
