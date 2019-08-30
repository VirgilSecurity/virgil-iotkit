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

#ifndef VIRGIL_IOT_SDK_GLOBAL_HAB_H
#define VIRGIL_IOT_SDK_GLOBAL_HAB_H

#include <stdint.h>
#include <stddef.h>

#define SERIAL_SIZE (32) /*This is size of SHA256 data*/
#define SERIAL_SIZE (32) /*This is size of SHA256 data*/
#define MANUFACTURE_ID_SIZE 16
#define DEVICE_TYPE_SIZE (4)
typedef struct __attribute__((__packed__)) {
    uint8_t app_type[4];
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
    uint8_t dev_milestone;
    uint8_t dev_build;
    uint32_t timestamp; //the number of seconds elapsed since January 1, 2015 UTC
} vs_firmware_version_t;

typedef struct  __attribute__((__packed__)) {
    uint8_t manufacture_id[MANUFACTURE_ID_SIZE];
    uint8_t device_type[DEVICE_TYPE_SIZE];
    vs_firmware_version_t version;
} vs_firmware_info_t;

typedef struct __attribute__((__packed__)) {
    vs_firmware_info_t info;
    uint8_t padding;
    uint16_t chunk_size;
    uint32_t firmware_length;
    uint32_t app_size; //firmware_length + fill_size + footer
} vs_firmware_descriptor_t;

void
vs_global_hal_msleep(size_t msec);

void
vs_global_hal_get_udid_of_device(uint8_t udid[SERIAL_SIZE]);

#endif // VIRGIL_IOT_SDK_GLOBAL_HAB_H
