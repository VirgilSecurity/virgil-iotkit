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

#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/protocols/sdmp/fldt_private.h>
#include <virgil/iot/protocols/sdmp/sdmp_private.h>
#include <virgil/iot/protocols/sdmp.h>
#include <endian-config.h>

static vs_sdmp_service_t _fldt_service = {0};
static bool _fldt_service_ready = false;

const vs_netif_t *vs_fldt_netif = NULL;
const vs_mac_addr_t *vs_fldt_broadcast_mac_addr = NULL;
bool vs_fldt_is_gateway;

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

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
char *
vs_fldt_file_type_descr(char *buf, const vs_fldt_file_type_t *file_type) {
    char *out = buf;
    const uint8_t *src;
    size_t pos;

    CHECK_NOT_ZERO(buf);
    CHECK_NOT_ZERO(file_type);

    VS_IOT_SPRINTF(out, "file type %d (add_info = \"", file_type->file_type_id);

    out += VS_IOT_STRLEN(buf);
    src = (const uint8_t *)&file_type->add_info;
    for (pos = 0; pos < sizeof(file_type->add_info); ++pos, ++out, ++src) {
        *out = !*src ? ' ' : (*src >= ' ' ? *src : '.');
    }

    VS_IOT_STRCPY(out, "\")");

    return buf;

terminate:

    return NULL;
}

/******************************************************************************/
char *
vs_fldt_file_version_descr(char *buf, const vs_fldt_file_version_t *file_ver) {
    static const uint32_t START_EPOCH = 1566203295; // January 1, 2015 UTC
    char *out = buf;
    CHECK_NOT_ZERO(buf);
    CHECK_NOT_ZERO(file_ver);

    vs_fldt_file_type_descr(out, &file_ver->file_type);
    out += VS_IOT_STRLEN(buf);

    // TODO : remove file type description!
    switch (file_ver->file_type.file_type_id) {
    case VS_UPDATE_FIRMWARE: {
        uint32_t timestamp = file_ver->fw_ver.timestamp + START_EPOCH;

        VS_IOT_SPRINTF(out,
                       ", ver %d.%d, patch %d, milestone %d, build %d, UNIX timestamp %u",
                       file_ver->fw_ver.major,
                       file_ver->fw_ver.minor,
                       file_ver->fw_ver.patch,
                       file_ver->fw_ver.dev_milestone,
                       file_ver->fw_ver.dev_build,
                       timestamp);
    } break;

    case VS_UPDATE_TRUST_LIST:
        VS_IOT_SPRINTF(out, ", ver %d", VS_IOT_NTOHS(file_ver->tl_ver));
        break;
    }

    return buf;

terminate:

    return NULL;
}

/******************************************************************************/
static int
_fldt_service_request_processor(const struct vs_netif_t *netif,
                                vs_sdmp_element_t element_id,
                                const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    *response_sz = 0;

    switch (element_id) {

    case VS_FLDT_INFV:
        return vs_fldt_INFV_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GFTI:
        if (vs_fldt_is_gateway) {
            return vs_fldt_GFTI_request_processing(request, request_sz, response, response_buf_sz, response_sz);
        } else {
            return VS_FLDT_ERR_OK;
        }

    case VS_FLDT_GNFH:
        return vs_fldt_GNFH_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GNFD:
        return vs_fldt_GNFD_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    case VS_FLDT_GNFF:
        return vs_fldt_GNFF_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    default:
        VS_IOT_ASSERT(false && "Unsupported command");
        return VS_FLDT_ERR_UNSUPPORTED_PARAMETER;
    }
}

/******************************************************************************/
static int
_fldt_service_response_processor(const struct vs_netif_t *netif,
                                 vs_sdmp_element_t element_id,
                                 bool is_ack,
                                 const uint8_t *response,
                                 const uint16_t response_sz) {

    switch (element_id) {

    case VS_FLDT_INFV:
        return VS_FLDT_ERR_OK;

    case VS_FLDT_GFTI:
        return vs_fldt_GFTI_response_processor(is_ack, response, response_sz);

    case VS_FLDT_GNFH:
        return vs_fldt_GNFH_response_processor(is_ack, response, response_sz);

    case VS_FLDT_GNFD:
        return vs_fldt_GNFD_response_processor(is_ack, response, response_sz);

    case VS_FLDT_GNFF:
        return vs_fldt_GNFF_response_processor(is_ack, response, response_sz);

    default:
        VS_IOT_ASSERT(false && "Unsupported command");
        return VS_FLDT_ERR_UNSUPPORTED_PARAMETER;
    }
}

/******************************************************************************/
static void
_prepare_fldt_service() {

    _fldt_service.user_data = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
    _fldt_service.id = HTONL_IN_COMPILE_TIME('FLDT');
#pragma GCC diagnostic pop
    _fldt_service.request_process = _fldt_service_request_processor;
    _fldt_service.response_process = _fldt_service_response_processor;
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_fldt_service(const vs_netif_t *netif) {

    if (!_fldt_service_ready) {
        _prepare_fldt_service();
        _fldt_service_ready = true;
    }

    vs_fldt_netif = netif;

    return &_fldt_service;
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
    packet->header.service_id = _fldt_service.id;
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