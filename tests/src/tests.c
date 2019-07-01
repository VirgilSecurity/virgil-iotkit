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

#include <helpers.h>
#include <stdlib.h>

uint16_t failed_test_result;

void
sdmp_tests(void);
void
prvs_tests(void);

void
test_hash(void);
void
test_hmac(void);
void
test_kdf2(void);
void
test_ecdsa(void);
void
test_ecdh(void);
void
test_keypair(void);
void
test_random(void);
void
test_aes(void);
void
test_sign_converters(void);
void
test_pubkeys_converters(void);

/**********************************************************/
static void
crypto_tests(void) {

    test_hash();
    test_hmac();
    test_kdf2();
    test_ecdsa();
    test_ecdh();
    test_keypair();
    test_random();
    test_aes();
#if !VIRGIL_IOT_MCU_BUILD
    test_sign_converters();
    test_pubkeys_converters();
#endif

}

/**********************************************************/
uint16_t
vs_tests_checks(bool print_start_finish_tests) {
    failed_test_result = 0;

    if(print_start_finish_tests){
        START_TESTS;
    }

    sdmp_tests();
    prvs_tests();

    crypto_tests();

    if(print_start_finish_tests){
        FINISH_TESTS;
    }

    return failed_test_result;
}

/**********************************************************/
void
vs_tests_begin(){
    START_TESTS;
}

/**********************************************************/
void
vs_tests_step_success(){
    RESULT_OK;
}

/**********************************************************/
void
vs_tests_step_failure(){
    RESULT_ERROR;
    terminate:;
}

/**********************************************************/
void
vs_tests_end(){
    FINISH_TESTS;
}
