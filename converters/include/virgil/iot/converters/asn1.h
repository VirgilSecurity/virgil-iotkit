/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file asn1.h
 * @brief Extremely simplified work with ASN.1
 */

#ifndef asn1_h
#define asn1_h

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define SEQUENCE 0x30
#define OCTET_STRING 0x04
#define INTEGER 0x02
#define BIT_STRING 0x03
#define ZERO_TAG 0xA0
#define OID 0x06
#define SET 0x31

#define ANS1_BUF_SIZE 1024

#ifdef __cplusplus
extern "C" {
#endif

bool
asn1_step_into(uint8_t element, int *pos, const int sz, const uint8_t *data);

bool
asn1_skip(uint8_t element, int *pos, const int sz, const uint8_t *data);

bool
asn1_get_array(uint8_t element, int *pos, const int sz, const uint8_t *data, const uint8_t **array, size_t *array_size);

bool
asn1_put_array(uint8_t element,
               int *pos,
               uint8_t *data,
               const uint8_t *array,
               size_t array_size,
               size_t *res_size,
               size_t *total_sz);

bool
asn1_put_raw(int *pos, uint8_t *data, const uint8_t *raw_data, size_t data_size, size_t *res_size, size_t *total_sz);

bool
asn1_put_header(uint8_t element, int *pos, uint8_t *data, size_t data_size, size_t *res_size, size_t *total_sz);

bool
asn1_put_header(uint8_t element, int *pos, uint8_t *data, size_t data_size, size_t *res_size, size_t *total_sz);

bool
asn1_put_uint8(int *pos, uint8_t *data, uint8_t val, size_t *res_size, size_t *total_sz);

size_t
asn1_get_size(int pos, const uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif /* asn1_h */
