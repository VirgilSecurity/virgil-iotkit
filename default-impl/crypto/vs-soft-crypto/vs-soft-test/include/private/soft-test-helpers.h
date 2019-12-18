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

#ifndef VS_TESTS_PRIVATE_HELPERS_H
#define VS_TESTS_PRIVATE_HELPERS_H

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/vs-soft-secmodule/vs-soft-slots-config.h>

#define TEST_RECOVERY_KEYPAIR_SLOT VS_KEY_SLOT_STD_MTP_10
#define TEST_AUTH_KEYPAIR_SLOT VS_KEY_SLOT_STD_MTP_11
#define TEST_TL_KEYPAIR_SLOT VS_KEY_SLOT_STD_MTP_12
#define TEST_FW_KEYPAIR_SLOT VS_KEY_SLOT_STD_MTP_13
#define TEST_USER_KEYPAIR_SLOT VS_KEY_SLOT_STD_MTP_14

const char *
vs_test_secmodule_slot_descr(vs_iot_secmodule_slot_e slot);
bool
vs_test_erase_otp_provision(vs_secmodule_impl_t *secmodule_impl);
bool
vs_test_create_device_key(vs_secmodule_impl_t *secmodule_impl);
bool
vs_test_save_hl_pubkeys(vs_secmodule_impl_t *secmodule_impl);
bool
vs_test_create_test_hl_keys(vs_secmodule_impl_t *secmodule_impl);
bool
vs_test_create_test_tl(vs_secmodule_impl_t *secmodule_impl);

#endif // VS_TESTS_PRIVATE_HELPERS_H
