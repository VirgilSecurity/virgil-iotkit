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

#include <stdlib-config.h>
#include <stdbool.h>

#include <virgil/iot/tests/helpers.h>
#include <virgil/iot/tests/tests.h>

#include <virgil/iot/provision/provision.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/firmware/firmware_hal.h>
#include <virgil/iot/protocols/snap.h>

/******************************************************************************/
static void
_str_to_bytes(uint8_t *dst, const char *src, size_t buf_size) {
    size_t pos;
    size_t len;

    VS_IOT_ASSERT(src && *src);

    VS_IOT_MEMSET(dst, 0, buf_size);

    len = VS_IOT_STRLEN(src);
    for (pos = 0; pos < len && pos < buf_size; ++pos, ++src, ++dst) {
        *dst = *src;
    }
}

/******************************************************************************/
vs_status_e
vs_firmware_get_own_firmware_footer_hal(void *footer, size_t footer_sz) {
    VS_IOT_ASSERT(footer);
    VS_IOT_ASSERT(footer_sz >= sizeof(vs_firmware_footer_t));

    CHECK_NOT_ZERO_RET(footer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(footer_sz >= sizeof(vs_firmware_footer_t), VS_CODE_ERR_INCORRECT_ARGUMENT, "buffer size too small");

    VS_IOT_MEMSET(footer, 0, footer_sz);
    vs_firmware_footer_t *buf = (vs_firmware_footer_t *)footer;

    _str_to_bytes(buf->descriptor.info.manufacture_id, TEST_MANUFACTURE_ID, sizeof(vs_device_manufacture_id_t));
    _str_to_bytes(buf->descriptor.info.device_type, TEST_DEVICE_TYPE, sizeof(vs_device_type_t));

    return VS_CODE_OK;
}
