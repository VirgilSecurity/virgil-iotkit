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

#include <stdlib-config.h>
#include <global-hal.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp/prvs.h>
#include <virgil/iot/tests/private/test_netif.h>
#include <virgil/iot/tests/private/test_prvs.h>

prvs_call_t prvs_call;
server_request_t server_request;
make_server_response_t make_server_response;

/**********************************************************/
static int
prvs_dnid() {

    prvs_call.dnid = 1;

    return 0;
}

/**********************************************************/
static int
prvs_save_data(vs_sdmp_prvs_element_e element_id, const uint8_t *data, uint16_t data_sz) {

    server_request.save_data.element_id = element_id;
    server_request.save_data.data_sz = data_sz;
    if (!(server_request.save_data.data = VS_IOT_MALLOC(data_sz))) {
        VS_IOT_ASSERT(false && "Unable to allocate memory");
        return -1;
    }
    VS_IOT_MEMCPY(server_request.save_data.data, data, data_sz);

    prvs_call.save_data = 1;

    return 0;
}

/**********************************************************/
static int
prvs_device_info(vs_sdmp_prvs_devi_t *device_info, uint16_t buf_sz) {

    server_request.finalize_storage.buf_sz = buf_sz;

    VS_IOT_MEMCPY(device_info,
                  make_server_response.device_info,
                  sizeof(vs_sdmp_prvs_devi_t) + make_server_response.device_info->data_sz);

    prvs_call.device_info = 1;

    return 0;
}

/**********************************************************/
static int
prvs_finalize_storage(vs_pubkey_t *asav_response, uint16_t *resp_sz) {
    VS_IOT_ASSERT(asav_response);

    prvs_call.finalize_storage = 1;
    *resp_sz = make_server_response.finalize_storage.size;
    memcpy(asav_response, &make_server_response.finalize_storage.asav_response, *resp_sz);

    return 0;
}

/**********************************************************/
static int
prvs_finalize_tl(const uint8_t *data, uint16_t data_sz) {

    server_request.finalize_tl.data_sz = data_sz;
    if (!(server_request.finalize_tl.data = VS_IOT_MALLOC(data_sz))) {
        VS_IOT_ASSERT(false && "Unable to allocate memory");
        return -1;
    }
    VS_IOT_MEMCPY(server_request.finalize_tl.data, data, data_sz);

    prvs_call.finalize_tl = 1;

    return 0;
}

/**********************************************************/
static int
prvs_stop_wait(int *condition, int expect) {

    VS_IOT_ASSERT(condition);

    *condition = expect;

    prvs_call.stop_wait = 1;

    return 0;
}

/**********************************************************/
static int
prvs_wait(uint32_t wait_ms, int *condition, int idle) {

    prvs_call.wait = 1;

    return 0;
}

/**********************************************************/
static int
sign_data(const uint8_t *data, uint16_t data_sz, uint8_t *signature, uint16_t buf_sz, uint16_t *signature_sz) {
    VS_IOT_ASSERT(buf_sz >= make_server_response.sign_data.signature_sz);

    if (!(server_request.sign_data.data = VS_IOT_MALLOC(data_sz))) {
        VS_IOT_ASSERT(false && "Unable to allocate memory");
        return -1;
    }
    VS_IOT_MEMCPY(server_request.sign_data.data, data, data_sz);
    server_request.sign_data.data_sz = data_sz;
    server_request.sign_data.buf_sz = buf_sz;
    VS_IOT_MEMCPY(signature, make_server_response.sign_data.signature, make_server_response.sign_data.signature_sz);

    *signature_sz = make_server_response.sign_data.signature_sz;

    prvs_call.sign_data = 1;

    return 0;
}

/**********************************************************/
vs_sdmp_prvs_impl_t
make_prvs_implementation(void) {
    vs_sdmp_prvs_impl_t prvs_impl;

    prvs_impl.dnid_func = prvs_dnid;
    prvs_impl.save_data_func = prvs_save_data;
    prvs_impl.load_data_func = NULL;
    prvs_impl.device_info_func = prvs_device_info;
    prvs_impl.finalize_storage_func = prvs_finalize_storage;
    prvs_impl.start_save_tl_func = NULL;
    prvs_impl.save_tl_part_func = NULL;
    prvs_impl.finalize_tl_func = prvs_finalize_tl;
    prvs_impl.sign_data_func = sign_data;
    prvs_impl.stop_wait_func = prvs_stop_wait;
    prvs_impl.wait_func = prvs_wait;

    return prvs_impl;
}
