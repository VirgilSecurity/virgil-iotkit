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

#ifndef IOT_RPI_FILE_IO_HAL_H
#define IOT_RPI_FILE_IO_HAL_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

void
vs_hal_files_set_mac(uint8_t mac_addr[6]);

void
vs_hal_files_set_dir(const char *dir_name);

ssize_t
vs_nix_get_file_len(const char *folder, const char *file_name);

bool
vs_nix_get_keystorage_base_dir(char *dir);

const char *
vs_nix_get_trust_list_dir(void);

const char *
vs_nix_get_firmware_dir(void);

const char *
vs_nix_get_secbox_dir(void);

bool
vs_nix_write_file_data(const char *folder, const char *file_name, uint32_t offset, const void *data, size_t data_sz);

bool
vs_nix_sync_file(const char *folder, const char *file_name);

bool
vs_nix_read_file_data(const char *folder,
                      const char *file_name,
                      uint32_t offset,
                      uint8_t *data,
                      size_t buf_sz,
                      size_t *read_sz);

bool
vs_nix_remove_file_data(const char *folder, const char *file_name);

#endif // IOT_RPI_FILE_IO_HAL_H
