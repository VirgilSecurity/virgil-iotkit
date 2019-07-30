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

#ifndef VIRGIL_IOT_SDK_GLOBAL_HAL_H
#define VIRGIL_IOT_SDK_GLOBAL_HAL_H

#include <stdint.h>

#define SERIAL_SIZE (32)

typedef struct __attribute__((__packed__)) {
    uint8_t app_type[4];
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
    uint8_t dev_milestone;
    uint8_t dev_build;
    uint32_t timestamp;
} vs_firmware_version_t;

typedef struct __attribute__((__packed__)) {
    uint8_t manufacture_id[16];
    uint8_t device_type[4];
    vs_firmware_version_t version;
    uint8_t padding;
    uint16_t chunk_size;
    uint32_t firmware_length;
    uint32_t app_size;
} vs_firmware_descriptor_t;

void *
platform_calloc(size_t num, size_t size);

void *
platform_malloc(size_t size);

void
platform_free(void *ptr);

void
vs_global_hal_msleep(size_t msec);

void
vs_global_hal_get_udid_of_device(uint8_t udid[SERIAL_SIZE]);

const vs_firmware_descriptor_t *
vs_global_hal_get_firmware_descriptor(void);

#endif // VIRGIL_IOT_SDK_GLOBAL_HAL_H
