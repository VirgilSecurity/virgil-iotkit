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

#ifndef VS_IOT_APP_HELPERS_H
#define VS_IOT_APP_HELPERS_H

#include <virgil/iot/protocols/snap.h>
char *
vs_app_get_commandline_arg(int argc, char *argv[], const char *shortname, const char *longname);

vs_status_e
vs_app_get_mac_from_commandline_params(int argc, char *argv[], vs_mac_addr_t *forced_mac_addr);

vs_status_e
vs_app_get_image_path_from_commandline_params(int argc, char *argv[], char **path);

void
vs_app_print_title(const char *devices_dir,
                   const char *app_file,
                   const char *manufacture_id_str,
                   const char *device_type_str);

void
vs_app_sleep_until_stop(void);

void
vs_app_restart(void);

bool
vs_app_data_to_hex(const uint8_t *_data, uint32_t _len, uint8_t *_out_data, uint32_t *_in_out_len);

void
vs_app_str_to_bytes(uint8_t *dst, const char *src, size_t elem_buf_size);

void
vs_app_get_serial(vs_device_serial_t serial, vs_mac_addr_t mac);

bool
vs_app_is_need_restart(void);

#endif // VS_IOT_APP_HELPERS_H
