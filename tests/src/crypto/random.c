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

#include <virgil/iot/tests/helpers.h>
#include <private/private_helpers.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <stdlib-config.h>

#if IOTELIC_MCU_BUILD
#define SEQUENCE_SIZE 1024
#else // IOTELIC_MCU_BUILD
#define SEQUENCE_SIZE 16384
#endif // IOTELIC_MCU_BUILD

/******************************************************************************/
#define STEPS 4
static int
_generate_random(vs_secmodule_impl_t *secmodule_impl, uint8_t *sequence) {
    static const size_t size_step = SEQUENCE_SIZE / STEPS;
    size_t pos;
    int res;

    for (pos = 0; pos < STEPS; ++pos) {
        res = secmodule_impl->random(sequence, size_step);

        if (VS_CODE_OK != res) {
            VS_LOG_ERROR("Unable to generate random number, step = %d", pos);
            return res;
        }

        if (pos) {
            CHECK_RET(VS_IOT_MEMCMP(sequence - size_step, sequence, size_step) != 0,
                      VS_CODE_ERR_CRYPTO,
                      "Sequence is the same as previous");
        }

        sequence += size_step;
    }

    return VS_CODE_OK;
}

#undef STEPS

/******************************************************************************/
//
// Count '0' and '1' bits amount
// Compare their amount
// It must be less that diff_treshold
//
static bool
_frequency_bits(uint8_t *sequence) {
    size_t bit_zero = 0;
    size_t bit_one = 0;
    size_t pos;
    size_t bit;
    uint8_t cur_byte;
    size_t difference;
    size_t limit = 30; // e-3

    for (pos = 0; pos < SEQUENCE_SIZE; ++pos) {
        cur_byte = *sequence;

        for (bit = 0; bit < 8; ++bit) {
            if (cur_byte & 1) {
                ++bit_one;
            } else {
                ++bit_zero;
            }

            cur_byte >>= 1;
        }

        ++sequence;
    }

    difference = bit_zero > bit_one ? bit_zero - bit_one : bit_one - bit_zero;
    difference *= 1000; // e-3
    difference /= SEQUENCE_SIZE * 8;
    BOOL_CHECK_RET(difference < limit,
                   "Bits frequency count : amount difference %de-3 is bigger that %de-3",
                   difference,
                   limit);


    return true;
}

/******************************************************************************/
//
// Count each byte amount
// Calculate frequency of each byte
// It must be less that diff_treshold
//
static bool
_frequency_bytes(uint8_t *sequence) {
    size_t byte[256] = {0};
    size_t cur_value;
    size_t pos;
    size_t max_amount = 0;
    uint8_t max_amount_pos = 0;
    size_t limit = 30; // e-3

    for (pos = 0; pos < SEQUENCE_SIZE; ++pos) {
        cur_value = ++byte[*sequence];

        if (cur_value > max_amount) {
            max_amount = cur_value;
            max_amount_pos = *sequence;
        }

        ++sequence;
    }

    max_amount *= 1000; // e-3
    max_amount /= SEQUENCE_SIZE;

    BOOL_CHECK_RET(max_amount < limit,
                   "Bytes frequency count : amount difference %de-3 for byte '%d' is bigger that %de-3",
                   max_amount,
                   (uint8_t)max_amount_pos,
                   limit);

    return true;
}

/******************************************************************************/
//
// Count difference for each two nearby bytes
// Calculate frequency of each difference
// It must be less that diff_treshold
//
static bool
_frequency_2bytes_diff(uint8_t *sequence) {
    size_t diff[2 * 256] = {0};
    size_t cur_value;
    int cur_diff;
    size_t pos;
    size_t limit = 30; // e-3
    size_t max_amount = 0;
    int8_t max_amount_pos = 0;

    for (pos = 1; pos < SEQUENCE_SIZE; ++pos) {
        cur_diff = (int)sequence[pos] - (int)sequence[pos - 1];
        cur_value = ++diff[256 + cur_diff];

        if (cur_value > max_amount) {
            max_amount = cur_value;
            max_amount_pos = cur_diff;
        }
    }

    max_amount *= 1000; // e-3
    max_amount /= SEQUENCE_SIZE;

    BOOL_CHECK_RET(max_amount < limit,
                   "Nearby bytes difference : amount %de-3 for difference '%d' is bigger that %de-3",
                   max_amount,
                   max_amount_pos,
                   limit);

    return true;
}

/******************************************************************************/
uint16_t
test_random(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;
    uint8_t sequence[SEQUENCE_SIZE];
    int res;

    START_TEST("Random tests");
    START_ELEMENT("Generate random sequence");
    res = _generate_random(secmodule_impl, sequence);
    if (VS_CODE_ERR_NOT_IMPLEMENTED == res) {
        VS_LOG_WARNING("Random function is not implemented");
        RESULT_OK;
    } else if (VS_CODE_OK != res) {
        RESULT_ERROR;
    }

    TEST_CASE_OK("\"Bits frequency\" test", _frequency_bits(sequence));
    TEST_CASE_OK("\"Bytes frequency\" test", _frequency_bytes(sequence));
    TEST_CASE_OK("\"Nearby bytes differences frequency\" test", _frequency_2bytes_diff(sequence));

terminate:
    return failed_test_result;
}
