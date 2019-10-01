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

#include <virgil/iot/protocols/sdmp/info.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_structs.h>
#include <endian-config.h>
#include <virgil/iot/protocols/sdmp/fldt_private.h>

// Commands
// mute "error: multi-character character constant" message
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
typedef enum {
    VS_INFO_GINF = HTONL_IN_COMPILE_TIME('GINF'), /* General INFormation */
} vs_sdmp_info_element_e;
#pragma GCC diagnostic pop

typedef struct __attribute__((__packed__)) {
    vs_fw_manufacture_id_t manufacture_id;
    vs_fw_device_type_t device_type;
    vs_mac_addr_t default_netif_mac;
    vs_firmware_version_t fw_version;
    uint16_t tl_version;
} vs_info_ginf_response_t;

static vs_storage_op_ctx_t *_tl_ctx;
static vs_storage_op_ctx_t *_fw_ctx;
static vs_fw_manufacture_id_t _manufacture_id;
static vs_fw_device_type_t _device_type;
#define FW_DESCR_BUF 128

/******************************************************************/
int
vs_info_GINF_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {
    vs_info_ginf_response_t *general_info = (vs_info_ginf_response_t *)response;
    vs_firmware_descriptor_t fw_descr;
    const vs_netif_t *defautl_netif;
    vs_tl_element_info_t tl_elem_info;
    vs_tl_header_t tl_header;
    uint16_t tl_header_sz = sizeof(tl_header);
    vs_status_code_e ret_code;
    char filever_descr[FW_DESCR_BUF];

    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(response_buf_sz > sizeof(vs_info_ginf_response_t), VS_CODE_ERR_TOO_SMALL_BUFFER, 0);

    defautl_netif = vs_sdmp_default_netif();

    CHECK_RET(!defautl_netif->mac_addr(&general_info->default_netif_mac),
              -1,
              "Cannot get MAC for Default Network Interface");

    STATUS_CHECK_RET(vs_firmware_load_firmware_descriptor(_fw_ctx, _manufacture_id, _device_type, &fw_descr),
                     "Unable to obtain Firmware's descriptor");

    tl_elem_info.id = VS_TL_ELEMENT_TLH;
    STATUS_CHECK_RET(vs_tl_load_part(&tl_elem_info, (uint8_t *)&tl_header, tl_header_sz, &tl_header_sz),
                     "Unable to obtain Trust List version");

    VS_IOT_MEMCPY(general_info->manufacture_id, _manufacture_id, sizeof(_manufacture_id));
    VS_IOT_MEMCPY(general_info->device_type, _device_type, sizeof(_device_type));
    VS_IOT_MEMCPY(&general_info->fw_version, &fw_descr.info.version, sizeof(fw_descr.info.version));
    general_info->tl_version = VS_IOT_NTOHS(tl_header.version);

    *response_sz = sizeof(vs_info_ginf_response_t);

    VS_LOG_DEBUG(
            "[INFO] Send current information: manufacture id = \"%s\", device type = \"%c%c%c%c\", firmware version = "
            "%s, trust list "
            "version = %d",
            general_info->manufacture_id,
            general_info->device_type[0],
            general_info->device_type[1],
            general_info->device_type[2],
            general_info->device_type[3],
            vs_firmware_describe_version(&general_info->fw_version, filever_descr, sizeof(filever_descr)),
            general_info->tl_version);

    return VS_CODE_OK;
}

/******************************************************************************/
static int
_info_request_processor(const struct vs_netif_t *netif,
                        vs_sdmp_element_t element_id,
                        const uint8_t *request,
                        const uint16_t request_sz,
                        uint8_t *response,
                        const uint16_t response_buf_sz,
                        uint16_t *response_sz) {
    (void)netif;

    *response_sz = 0;

    switch (element_id) {

    case VS_INFO_GINF:
        return vs_info_GINF_request_processing(request, request_sz, response, response_buf_sz, response_sz);

    default:
        VS_LOG_ERROR("Unsupported INFO command");
        VS_IOT_ASSERT(false);
        return VS_SDMP_COMMAND_NOT_SUPPORTED;
    }
}

/******************************************************************************/
const vs_sdmp_service_t *
vs_sdmp_info(vs_storage_op_ctx_t *tl_ctx,
             vs_storage_op_ctx_t *fw_ctx,
             const vs_fw_manufacture_id_t manufacturer_id,
             const vs_fw_device_type_t device_type) {

    static vs_sdmp_service_t _info = {0};

    CHECK_NOT_ZERO_RET(tl_ctx, NULL);
    CHECK_NOT_ZERO_RET(fw_ctx, NULL);

    _tl_ctx = tl_ctx;
    _fw_ctx = fw_ctx;
    VS_IOT_MEMCPY(_manufacture_id, manufacturer_id, sizeof(_manufacture_id));
    VS_IOT_MEMCPY(_device_type, device_type, sizeof(_device_type));

    _info.user_data = NULL;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
    _info.id = HTONL_IN_COMPILE_TIME('INFO');
#pragma GCC diagnostic pop
    _info.request_process = _info_request_processor;
    _info.response_process = NULL;

    return &_info;
}

/******************************************************************************/