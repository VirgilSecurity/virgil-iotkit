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

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <update-config.h>

#include <stdlib-config.h>
#include <update-config.h>

#include <defaults/storage/storage-esp-impl.h>
#include <helpers/file-io.h>

/******************************************************************************/
vs_status_e __attribute__((weak)) vs_firmware_install_prepare_space_hal(void) {
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e __attribute__((weak)) vs_firmware_install_append_data_hal(const void *data, uint16_t data_sz) {
    return VS_CODE_OK;;
}

/******************************************************************************/
int __attribute__((weak)) vs_firmware_nix_update(int argc, char **argv) {
    return 0;
}

/******************************************************************************/
vs_status_e __attribute__((weak)) vs_firmware_get_own_firmware_footer_hal(void *footer, size_t footer_sz) {
    return VS_CODE_OK;;
}

/******************************************************************************/
void __attribute__((weak)) vs_firmware_nix_set_info(const char *app_file, const vs_device_manufacture_id_t manufacture_id_str, const vs_device_type_t device_type_str) {

}

/******************************************************************************/
