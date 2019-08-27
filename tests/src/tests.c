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

#include <stdlib.h>
#include <virgil/iot/tests/helpers.h>
#include <fldt-config.h>

uint16_t
sdmp_tests(void);
uint16_t
prvs_tests(void);
uint16_t
fldt_tests(vs_fldt_file_type_id_t elem1, vs_fldt_file_type_id_t elem2, vs_fldt_file_type_id_t elem3);

uint16_t
test_hash(void);
uint16_t
test_hmac(void);
uint16_t
test_kdf2(void);
uint16_t
test_ecdsa(void);
uint16_t
test_ecdh(void);
uint16_t
test_keypair(void);
uint16_t
test_random(void);
uint16_t
test_aes(void);
uint16_t
test_sign_converters(void);
uint16_t
test_pubkeys_converters(void);
uint16_t
test_keystorage_and_tl(void);
/**********************************************************/
static uint16_t
crypto_tests(void) {
    uint16_t failed_test_result = 0;

    failed_test_result = test_hash();
    failed_test_result += test_hmac();
    failed_test_result += test_kdf2();
    failed_test_result += test_random();
    failed_test_result += test_aes();
    failed_test_result += test_keystorage_and_tl();
    failed_test_result += test_keypair();
    failed_test_result += test_ecdsa();
    failed_test_result += test_ecdh();
#if !VIRGIL_IOT_MCU_BUILD
    failed_test_result += test_sign_converters();
    failed_test_result += test_pubkeys_converters();
#endif
    return failed_test_result;
}

/**********************************************************/
uint16_t
vs_tests_checks(bool print_start_finish_tests, vs_fldt_file_type_id_t elem1, vs_fldt_file_type_id_t elem2, vs_fldt_file_type_id_t elem3) {
    uint16_t failed_test_result = 0;

    if(print_start_finish_tests){
    	START_TESTS;
    }
    
    failed_test_result = sdmp_tests();
    failed_test_result += prvs_tests();
    failed_test_result += fldt_tests(elem1, elem2, elem3);

    failed_test_result += crypto_tests();

    if (print_start_finish_tests) {
        FINISH_TESTS;
    }

    return failed_test_result;
}
