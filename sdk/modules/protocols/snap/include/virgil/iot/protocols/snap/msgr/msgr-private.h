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

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_MSGR_PRIVATE_H
#define VS_SECURITY_SDK_SNAP_SERVICES_MSGR_PRIVATE_H

#include <virgil/iot/protocols/snap/msgr/msgr-server.h>
#include <virgil/iot/protocols/snap/msgr/msgr-structs.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/protocols/snap/snap-structs.h>

// mute "error: multi-character character constant" message
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
typedef enum { VS_MSGR_SERVICE_ID = HTONL_IN_COMPILE_TIME('MSGR') } vs_msgr_t;

typedef enum {
    VS_MSGR_SNOT = HTONL_IN_COMPILE_TIME('SNOT'), /* Start NOTification */
    VS_MSGR_ENUM = HTONL_IN_COMPILE_TIME('ENUM'), /* ENUMerate devices */
    VS_MSGR_GETD = HTONL_IN_COMPILE_TIME('GETD'), /* GET Data from a device*/
    VS_MSGR_SETD = HTONL_IN_COMPILE_TIME('SETD'), /* SET Data to a device*/
    VS_MSGR_STAT = HTONL_IN_COMPILE_TIME('STAT'), /* STATus data of a device*/
    VS_MSGR_POLL = HTONL_IN_COMPILE_TIME('POLL'), /* Enable/disable POLLing */
} vs_snap_msgr_element_e;
#pragma GCC diagnostic pop

typedef struct __attribute__((__packed__)) {
    vs_mac_addr_t mac;
} vs_msgr_enum_response_t;

typedef struct __attribute__((__packed__)) {
    uint8_t enable;
    uint16_t period_seconds;
    vs_mac_addr_t recipient_mac;
} vs_msgr_poll_request_t;

typedef struct __attribute__((__packed__)) {
    uint32_t data_sz;
    uint8_t data[];
} vs_msgr_getd_response_t;

typedef struct __attribute__((__packed__)) {
    uint32_t data_sz;
    uint8_t data[];
} vs_msgr_setd_request_t;

#endif // VS_SECURITY_SDK_SNAP_SERVICES_MSGR_PRIVATE_H
