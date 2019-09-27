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

#include <virgil/iot/protocols/sdmp/fldt_private.h>
#include <virgil/iot/protocols/sdmp/sdmp_private.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/macros/macros.h>
#include <endian-config.h>
#include <stdlib-config.h>

/******************************************************************/
vs_fldt_ret_code_e
vs_firmware_version_2_vs_fldt_file_version(vs_fldt_file_version_t *dst,
                                           const vs_fldt_file_type_t *file_type,
                                           const void *src) {

    const vs_firmware_version_t *fw_src = (const vs_firmware_version_t *)src;
    const uint16_t *tl_src = (const uint16_t *)src;

    CHECK_NOT_ZERO_RET(dst, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_type, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(src, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    dst->file_type = *file_type;

    VS_LOG_INFO(">>> DEBUG 4.6.1.1");

    switch (file_type->file_type_id) {
    case VS_UPDATE_FIRMWARE:
        dst->fw_ver.major = fw_src->major;
        dst->fw_ver.minor = fw_src->minor;
        dst->fw_ver.patch = fw_src->patch;
        dst->fw_ver.dev_milestone = fw_src->dev_milestone;
        dst->fw_ver.dev_build = fw_src->dev_build;
        dst->fw_ver.timestamp = fw_src->timestamp;
        break;

    case VS_UPDATE_TRUST_LIST:
        dst->tl_ver = VS_IOT_NTOHS(*tl_src);
        break;
    }

    VS_LOG_INFO(">>> DEBUG 4.6.1.2");

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
const char *
vs_fldt_file_type_descr(char buf[FLDT_FILEVER_BUF], const vs_fldt_file_type_t *file_type) {
    char *out = buf;
    const uint8_t *src;
    size_t i;

    CHECK_NOT_ZERO(buf);
    CHECK_NOT_ZERO(file_type);

    out += VS_IOT_SPRINTF(out, "file type %d (add_info = \"", (int)file_type->file_type_id);

    src = (const uint8_t *)file_type->add_info;
    for (i = 0; i < sizeof(file_type->add_info); ++i, ++out, ++src) {
        if (*src >= 32 && *src <= 126) {
            *out = *src;
        } else {
            *out = '.';
        }
    }

    VS_IOT_STRCPY(out, "\")");

    return buf;

terminate:

    return "";
}

/******************************************************************************/
char *
vs_fldt_file_version_descr(char *buf, const vs_fldt_file_version_t *file_ver) {
    //    static const uint32_t START_EPOCH = 1420070400; // January 1, 2015 UTC
    //    char *out = buf;
    CHECK_NOT_ZERO(buf);
    //    CHECK_NOT_ZERO(file_ver);
    //    VS_LOG_INFO(">>> DEBUG 4.6.3.1");
    //
    //    vs_fldt_file_type_descr(out, &file_ver->file_type);
    //    out += VS_IOT_STRLEN(buf);
    //
    //    VS_LOG_INFO(">>> DEBUG 4.6.3.2");
    //
    //    // TODO : remove file type description!
    //    switch (file_ver->file_type.file_type_id) {
    //    case VS_UPDATE_FIRMWARE: {
    //        VS_LOG_INFO(">>> DEBUG 4.6.3.3");
    //#ifdef VS_IOT_ASCTIME
    //        time_t timestamp = file_ver->fw_ver.timestamp + START_EPOCH;
    //#else
    //        uint32_t timestamp = file_ver->fw_ver.timestamp + START_EPOCH;
    //#endif //   VS_IOT_ASCTIME
    //
    //        VS_IOT_SPRINTF(out,
    //#ifdef VS_IOT_ASCTIME
    //                       ", ver %d.%d.%d.%c.%d, %s",
    //#else
    //                       ", ver %d.%d.%d.%c.%d, UNIX timestamp %u",
    //#endif //   VS_IOT_ASCTIME
    //                       file_ver->fw_ver.major,
    //                       file_ver->fw_ver.minor,
    //                       file_ver->fw_ver.patch,
    //                       file_ver->fw_ver.dev_milestone,
    //                       file_ver->fw_ver.dev_build,
    //#ifdef VS_IOT_ASCTIME
    //                       VS_IOT_ASCTIME(timestamp)
    //#else
    //                       timestamp
    //#endif //   VS_IOT_ASCTIME
    //        );
    //    } break;
    //
    //    case VS_UPDATE_TRUST_LIST:
    //        VS_LOG_INFO(">>> DEBUG 4.6.3.5");
    //        VS_IOT_SPRINTF(out, ", ver %d", VS_IOT_NTOHS(file_ver->tl_ver));
    //        break;
    //    }
    //
    //    VS_LOG_INFO(">>> DEBUG 4.6.3.6");
    //
    //    return buf;
    //
    return (char *)"test";
terminate:

    return NULL;
}


/******************************************************************************/
int
vs_fldt_send_request(const vs_netif_t *netif,
                     const vs_mac_addr_t *mac,
                     vs_sdmp_fldt_element_e element,
                     const uint8_t *data,
                     uint16_t data_sz) {

    uint8_t buffer[sizeof(vs_sdmp_packet_t) + data_sz];
    vs_sdmp_packet_t *packet;

    VS_IOT_ASSERT(data);
    VS_IOT_ASSERT(data_sz);

    VS_IOT_MEMSET(buffer, 0, sizeof(buffer));

    // Prepare pointers
    packet = (vs_sdmp_packet_t *)buffer;

    // Prepare request
    packet->header.element_id = element;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
    packet->header.service_id = VS_FLDT_SERVICE_ID;
#pragma GCC diagnostic pop
    packet->header.content_size = data_sz;
    if (data_sz) {
        VS_IOT_MEMCPY(packet->content, data, data_sz);
    }
    _sdmp_fill_header(mac, packet);

    // Send request
    return vs_sdmp_send(netif, buffer, sizeof(vs_sdmp_packet_t) + packet->header.content_size);
}

/******************************************************************************/
bool
vs_fldt_file_is_newer(const vs_fldt_file_version_t *available, const vs_fldt_file_version_t *current) {

    VS_IOT_ASSERT(available);
    VS_IOT_ASSERT(current);
    VS_IOT_ASSERT(!VS_IOT_MEMCMP(&available->file_type, &current->file_type, sizeof(available->file_type)) &&
                  "Different file types");

    // TODO : compare versions like this !

    //    0 <= VS_IOT_MEMCMP(&current_ver.major,
    //                       &new_ver->major,
    //                       sizeof(vs_firmware_version_t) - sizeof(current_ver.app_type)))

    // TODO : remove file type description!
    switch (available->file_type.file_type_id) {
    case VS_UPDATE_FIRMWARE:
        VS_IOT_ASSERT(available->fw_ver.timestamp);

        return !current->fw_ver.timestamp || available->fw_ver.major > current->fw_ver.major ||
               available->fw_ver.minor > current->fw_ver.minor || available->fw_ver.patch > current->fw_ver.patch ||
               available->fw_ver.dev_milestone > current->fw_ver.dev_milestone;

    case VS_UPDATE_TRUST_LIST:
        return VS_IOT_NTOHS(available->tl_ver) > VS_IOT_NTOHS(current->tl_ver);

    default:
        // TODO : process any file type!
        return true;
    }
}

/******************************************************************************/