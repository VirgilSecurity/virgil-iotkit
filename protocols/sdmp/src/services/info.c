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

// Commands
// mute "error: multi-character character constant" message
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
typedef enum {
    VS_INFO_GINF = HTONL_IN_COMPILE_TIME('GINF'), /* General INFormation */
} vs_sdmp_info_element_e;
#pragma GCC diagnostic pop

typedef struct __attribute__((__packed__)) {
    vs_mac_addr_t default_netif_mac;
} vs_info_ginf_response_t;

/******************************************************************/
int
vs_info_GINF_request_processing(const uint8_t *request,
                                const uint16_t request_sz,
                                uint8_t *response,
                                const uint16_t response_buf_sz,
                                uint16_t *response_sz) {

    vs_info_ginf_response_t *general_info = (vs_info_ginf_response_t *)response;
    const vs_netif_t *defautl_netif;

    CHECK_NOT_ZERO_RET(response, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(response_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_RET(response_buf_sz > sizeof(vs_info_ginf_response_t), VS_CODE_ERR_TOO_SMALL_BUFFER, 0);


    defautl_netif = vs_sdmp_default_netif();
    CHECK_RET(defautl_netif->mac_addr(&general_info->default_netif_mac),
              -1,
              "Cannot get MAC for Default Network Interface");

    *response_sz = sizeof(vs_info_ginf_response_t);

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
vs_sdmp_info(void) {

    static vs_sdmp_service_t _info = {0};

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