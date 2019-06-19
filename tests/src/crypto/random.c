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
#include <virgil/iot/hsm/hsm_interface.h>

#if IOTELIC_MCU_BUILD
#define SEQUENCE_SIZE 256
#else // IOTELIC_MCU_BUILD
#define SEQUENCE_SIZE 16384
#endif // IOTELIC_MCU_BUILD

/******************************************************************************/
#define STEPS 4
static bool
_generate_random(uint8_t *sequence) {
    static const size_t size_step = SEQUENCE_SIZE / STEPS;
    size_t pos;

    for (pos = 0; pos < STEPS; ++pos) {
        VS_HSM_CHECK_RET(vs_hsm_random(sequence, size_step), "Unable to generate random number, step = %d", pos);

        if (pos) {
            BOOL_CHECK_RET(memcmp(sequence - size_step, sequence, size_step) != 0, "Sequence is the same as previous");
        }

        sequence += size_step;
    }

    return true;
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
    float difference;
    float diff_treshold = 0.05;

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
    difference /= SEQUENCE_SIZE * 8;
    BOOL_CHECK_RET(difference < diff_treshold,
                   "Bits frequency count : amount difference %.2f is bigger than threshold %.2f",
                   difference,
                   diff_treshold);

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
    static const size_t elements = sizeof(byte) / sizeof(byte[0]);
    size_t pos;
    float difference;
    float diff_treshold = 2;

    for (pos = 0; pos < SEQUENCE_SIZE; ++pos) {
        ++byte[*sequence];
        ++sequence;
    }

    for (pos = 0; pos < sizeof(byte) / sizeof(byte[0]); ++pos) {
        difference = byte[pos];
        difference /= SEQUENCE_SIZE;
        difference *= elements;
        BOOL_CHECK_RET(difference < diff_treshold,
                       "Bytes frequency count : amount difference %.5f for byte = %d is bigger than threshold %.5f",
                       difference,
                       (uint8_t)pos,
                       diff_treshold);
    }

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
    static const size_t elements = sizeof(diff) / sizeof(diff[0]);
    int cur_diff;
    size_t pos;
    float diff_treshold = 3;
    float difference;

    for (pos = 1; pos < SEQUENCE_SIZE; ++pos) {
        cur_diff = (int)sequence[0] - sequence[-1];
        ++diff[256 + cur_diff];
        ++sequence;
    }

    for (pos = 0; pos < sizeof(diff) / sizeof(diff[0]); ++pos) {
        difference = diff[pos];
        difference /= SEQUENCE_SIZE;
        difference *= elements;
        if (difference >= diff_treshold) {
            cur_diff = pos - 256;
            BOOL_CHECK_RET(difference < diff_treshold,
                           "Nearby bytes difference : amount %.5f for difference %d is bigger than threshold %.5f",
                           difference,
                           cur_diff,
                           diff_treshold);
        }
    }

    return true;
}

/******************************************************************************/
void
test_random(void) {
    uint8_t sequence[SEQUENCE_SIZE];

    START_TEST("Random tests");

    TEST_CASE_OK("Generate random sequence", _generate_random(sequence));
    TEST_CASE_OK("\"Bits frequency\" test", _frequency_bits(sequence));
    TEST_CASE_OK("\"Bytes frequency\" test", _frequency_bytes(sequence));
    TEST_CASE_OK("\"Nearby bytes differences frequency\" test", _frequency_2bytes_diff(sequence));

terminate:;
}
