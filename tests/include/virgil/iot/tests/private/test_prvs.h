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

#ifndef VIRGIL_IOT_SDK_TESTS_PRVS_H_
#define VIRGIL_IOT_SDK_TESTS_PRVS_H_

#include <helpers.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp/PRVS.h>

typedef struct {
    union {
        uint16_t call;

        struct {
            unsigned dnid : 1;
            unsigned save_data : 1;
            unsigned load_data : 1;
            unsigned device_info : 1;
            unsigned finalize_storage : 1;
            unsigned start_save : 1;
            unsigned save_tl_part : 1;
            unsigned finalize_tl : 1;
            unsigned sign_data : 1;
            unsigned stop_wait : 1;
            unsigned wait : 1;
            unsigned request : 1;
            unsigned response : 1;
        };
    };
} prvs_call_t;

typedef union {

    struct {
        size_t buf_sz;
    } finalize_storage;

    struct {
        uint8_t *data;
        size_t data_sz;
        size_t buf_sz;
    } sign_data;

    struct {
        vs_sdmp_prvs_element_t element_id;
        uint8_t *data;
        size_t data_sz;
    } save_data;

    struct {
        uint8_t *data;
        size_t data_sz;
    } finalize_tl;

} server_request_t;

typedef union {
    struct {
        vs_sdmp_pubkey_t asav_response;
    } finalize_storage;

    vs_sdmp_prvs_devi_t *device_info;

    struct {
        uint8_t *signature;
        size_t signature_sz;
    } sign_data;

    struct {
        vs_sdmp_prvs_element_t element_id;
        uint8_t *data;
        size_t data_sz;
    } save_data;

} make_server_response_t;

/*
typedef union {

    struct {
        vs_sdmp_prvs_element_t element_id;
        uint8_t *data;
        size_t data_sz;
    } save_data;
        struct {
            vs_sdmp_prvs_devi_t *device_info;
            size_t buf_sz;
        } data_device_info;

        struct {
            vs_sdmp_pubkey_t *asav_response;
        } data_finalize_storage;

        struct {
            uint8_t *data;
            size_t data_sz;
        } data_start_save_tl;

        struct {
            uint8_t *data;
            size_t data_sz;
        } data_save_tl_part;

        struct {
            uint8_t *data;
            size_t data_sz;
        } data_finalize_tl;

        struct {
            uint8_t *data;
            size_t data_sz;
            uint8_t *signature;
            size_t buf_sz;
            size_t *signature_sz;
        } data_sign_data;
    };
*/

extern prvs_call_t prvs_call;
extern server_request_t server_request;
extern make_server_response_t make_server_response;

void prepare_prvs_service(vs_sdmp_service_t *prvs_service);
vs_sdmp_prvs_impl_t make_prvs_implementation(void);

#define PRVS_OP_CHECK_GOTO(OPERATION) BOOL_CHECK_GOTO((OPERATION) != 0, "prvs operation " # OPERATION " has not been called");

#define PRVS_ALLOC_AND_COPY(DST_BUF, DST_SIZE, SRC_BUF, SRC_SIZE)   do { \
        VS_IOT_ASSERT(SRC_BUF); \
        if (SRC_SIZE) {   \
            (DST_BUF) = VS_IOT_MALLOC(SRC_BUF); \
            VS_IOT_ASSERT(DST_BUF); \
            VS_IOT_MEMCPY((DST_BUF), (SRC_BUF), (SRC_SIZE));    \
            (DST_SIZE) = (SRC_SIZE);    \
        } else {    \
            DST_BUF = NULL; \
            DST_SIZE = 0;   \
        }   \
        } while(0)

#endif // VIRGIL_IOT_SDK_TESTS_PRVS_H_
