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
 * @file asn1.c
 * @brief Extremely simplified work with ASN.1
 */

#include <virgil/iot/converters/asn1.h>
#include <string.h>

/******************************************************************************/
bool
asn1_step_into(uint8_t element, int *pos, const int sz, const uint8_t *data) {
    if (element != data[*pos] || (2 + *pos) >= sz)
        return false;

    if (data[1 + *pos] >= 0x80) {
        *pos += data[1 + *pos] & 0x0F;
    }
    *pos += 2;

    return true;
}

/******************************************************************************/
bool
asn1_skip(uint8_t element, int *pos, const int sz, const uint8_t *data) {
    size_t element_sz, sz_bytes;
    if (element != data[*pos])
        return false;

    if (0x80 > data[1 + *pos]) {
        element_sz = data[1 + *pos];
        *pos += 2 + element_sz;
    } else {
        sz_bytes = data[1 + *pos] & 0x0F;
        element_sz = data[2 + *pos];
        if (2 == sz_bytes) {
            element_sz <<= 8;
            element_sz += data[3 + *pos];
        }
        *pos += 2 + sz_bytes + element_sz;
    }
    return true;
}

/******************************************************************************/
bool
asn1_get_array(uint8_t element,
               int *pos,
               const int sz,
               const uint8_t *data,
               const uint8_t **array,
               size_t *array_size) {
    size_t element_sz;
    if (element == data[*pos]) {
        element_sz = data[1 + *pos];
        if (0x80 > element_sz) {
            *array_size = element_sz;
            *array = &data[2 + *pos];
            *pos += 2 + element_sz;
            return true;
        }
    }
    return false;
}

/******************************************************************************/
bool
asn1_put_array(uint8_t element,
               int *pos,
               uint8_t *data,
               const uint8_t *array,
               size_t array_size,
               size_t *res_size,
               size_t *total_sz) {
    int prefix_sz = 2;
    uint8_t *w;

    if (INTEGER == element && array[0] >= 0x80) {
        prefix_sz += 1;
    }
    *res_size = array_size + prefix_sz;

    if (*pos > *res_size) {
        w = &data[*pos - *res_size];
        w[0] = element;
        w[1] = array_size + prefix_sz - 2;

        if (prefix_sz > 2) {
            w[2] = 0x00;
            w += 3;
        } else {
            w += 2;
        }
        memcpy(w, array, array_size);
        *pos -= *res_size;
        if (total_sz) {
            *total_sz += *res_size;
        }
        return true;
    }
    return false;
}

/******************************************************************************/
bool
asn1_put_header(uint8_t element, int *pos, uint8_t *data, size_t data_size, size_t *res_size, size_t *total_sz) {
    uint8_t *w;
    *res_size = data_size < 0x80 ? 2 : 4;

    if (*pos > *res_size) {
        w = &data[*pos - *res_size];
        w[0] = element;
        if (data_size < 0x80) {
            w[1] = data_size;
        } else {
            w[1] = 0x82;
            w[2] = data_size >> 8;
            w[3] = data_size & 0xFF;
        }
        *pos -= *res_size;
        if (total_sz) {
            *total_sz += *res_size;
        }
        return true;
    }
    return false;
}

/******************************************************************************/
bool
asn1_put_uint8(int *pos, uint8_t *data, uint8_t val, size_t *res_size, size_t *total_sz) {
    uint8_t *w;

    *res_size = 3;

    if (*pos > *res_size) {
        w = &data[*pos - *res_size];
        w[0] = INTEGER;
        w[1] = 1;
        w[2] = val;
        *pos -= *res_size;
        if (total_sz) {
            *total_sz += *res_size;
        }
        return true;
    }
    return false;
}

/******************************************************************************/
bool
asn1_put_raw(int *pos, uint8_t *data, const uint8_t *raw_data, size_t data_size, size_t *res_size, size_t *total_sz) {
    uint8_t *w;

    *res_size = data_size;

    if (*pos > *res_size) {
        w = &data[*pos - *res_size];
        memcpy(w, raw_data, data_size);
        *pos -= *res_size;
        if (total_sz) {
            *total_sz += *res_size;
        }
        return true;
    }
    return false;
}

/******************************************************************************/
size_t
asn1_get_size(int pos, const uint8_t *data) {
    size_t i, cnt = 0, res = 0;

    if (data[1 + pos] > 0x80) {
        cnt = data[1 + pos] & 0x7F;
        if (cnt > 2)
            return res;

        for (i = 0; i < cnt; ++i) {
            res <<= 8;
            res |= data[2 + i + pos];
        }

        res += 2 + cnt;
    } else {
        res = data[1 + pos] + 2;
    }

    return res;
}
