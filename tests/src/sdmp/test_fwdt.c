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
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <virgil/iot/protocols/sdmp/FWDT.h>
#include <virgil/iot/tests/private/test_netif.h>
#include <virgil/iot/tests/private/test_fwdt.h>

fwdt_call_t fwdt_call;
server_request_t server_request;
make_server_response_t make_server_response;

/**********************************************************/
static int
fwdt_dnid() {

    fwdt_call.dnid = 1;

    return 0;
}

/**********************************************************/
static int
fwdt_stop_wait(int *condition, int expect) {

    VS_IOT_ASSERT(condition);

    *condition = expect;

    fwdt_call.stop_wait = 1;

    return 0;
}

/**********************************************************/
static int
fwdt_wait(uint32_t wait_ms, int *condition, int idle) {

    fwdt_call.wait = 1;

    return 0;
}

/**********************************************************/
vs_sdmp_fwdt_impl_t
make_fwdt_implementation(void) {
    vs_sdmp_fwdt_impl_t fwdt_impl;

    fwdt_impl.dnid_func = fwdt_dnid;
    fwdt_impl.stop_wait_func = fwdt_stop_wait;
    fwdt_impl.wait_func = fwdt_wait;

    return fwdt_impl;
}
