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

#include <stdlib.h>
#include <virgil/iot/secmodule/secmodule.h>

uint16_t
test_hash(vs_secmodule_impl_t *secmodule_impl);
uint16_t
test_hmac(vs_secmodule_impl_t *secmodule_impl);
uint16_t
test_kdf2(vs_secmodule_impl_t *secmodule_impl);
uint16_t
test_ecdsa(vs_secmodule_impl_t *secmodule_impl);
uint16_t
test_ecdh(vs_secmodule_impl_t *secmodule_impl);
uint16_t
test_keypair(vs_secmodule_impl_t *secmodule_impl);
uint16_t
test_random(vs_secmodule_impl_t *secmodule_impl);
uint16_t
test_aes(vs_secmodule_impl_t *secmodule_impl);
uint16_t
test_sign_converters(void);
uint16_t
test_pubkeys_converters(void);
uint16_t
test_keystorage_and_tl(vs_secmodule_impl_t *secmodule_impl);
uint16_t
vs_virgil_ecies_test(vs_secmodule_impl_t *secmodule_impl);

/**********************************************************/
uint16_t
vs_crypto_test(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;

    VS_IOT_ASSERT(secmodule_impl);
    CHECK_NOT_ZERO_RET(secmodule_impl, 1);

    failed_test_result = test_hash(secmodule_impl);
    failed_test_result += test_hmac(secmodule_impl);
    failed_test_result += test_kdf2(secmodule_impl);
    failed_test_result += test_random(secmodule_impl);
    failed_test_result += test_aes(secmodule_impl);
    failed_test_result += test_keypair(secmodule_impl);
    failed_test_result += test_keystorage_and_tl(secmodule_impl);
    failed_test_result += test_ecdsa(secmodule_impl);
    failed_test_result += test_ecdh(secmodule_impl);
    failed_test_result += vs_virgil_ecies_test(secmodule_impl);
#if !VIRGIL_IOT_MCU_BUILD
    failed_test_result += test_sign_converters();
    failed_test_result += test_pubkeys_converters();
#endif

    return failed_test_result;
}
