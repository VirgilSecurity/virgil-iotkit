/**
 * \file
 * \brief Software implementation of the SHA256 algorithm.
 *
 * Copyright (c) 2015 Atmel Corporation. All rights reserved.
 *
 * \atmel_crypto_device_library_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \atmel_crypto_device_library_license_stop
 */

#include <string.h>
#include "virgil/iot/hsm/hsm_sw_sha2_routines.h"

#define rotate_right(value, places) ((value >> places) | (value << (32 - places)))

/**
 * \brief Processes whole blocks (64 bytes) of data.
 *
 * \param[in] ctx          SAH256 hash context
 * \param[in] blocks       Raw blocks to be processed
 * \param[in] block_count  Number of 64-byte blocks to process
 */
static void
_sw_sha256_process(vs_hsm_sw_sha256_ctx *ctx, const uint8_t *blocks, uint32_t block_count){
	int i = 0;
	uint32_t block = 0;

	union {
		uint32_t w_word[SHA256_BLOCK_SIZE];
		uint8_t w_byte[SHA256_BLOCK_SIZE * sizeof(uint32_t)];
	} w_union;

	static const uint32_t k[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	// Loop through all the blocks to process
	for (block = 0; block < block_count; block++) {
		uint32_t w_index;
		uint32_t word_value;
		uint32_t s0, s1;
		uint32_t t1, t2;
		uint32_t maj, ch;
		uint32_t rotate_register[8];
		const uint8_t* cur_msg_block = &blocks[block * SHA256_BLOCK_SIZE];

		// Swap word bytes
		for (i = 0; i < SHA256_BLOCK_SIZE; i += 4) {
			w_union.w_byte[i + 3] = cur_msg_block[i + 0];
			w_union.w_byte[i + 2] = cur_msg_block[i + 1];
			w_union.w_byte[i + 1] = cur_msg_block[i + 2];
			w_union.w_byte[i + 0] = cur_msg_block[i + 3];
		}

		w_index = 16;
		while (w_index < SHA256_BLOCK_SIZE) {
			// right rotate for 32-bit variable in C: (value >> places) | (value << 32 - places)
			word_value = w_union.w_word[w_index - 15];
			s0 = rotate_right(word_value, 7) ^ rotate_right(word_value, 18) ^ (word_value >> 3);

			word_value = w_union.w_word[w_index - 2];
			s1 = rotate_right(word_value, 17) ^ rotate_right(word_value, 19) ^ (word_value >> 10);

			w_union.w_word[w_index] = w_union.w_word[w_index - 16] + s0 + w_union.w_word[w_index - 7] + s1;

			w_index++;
		}

		// Initialize hash value for this chunk.
		memcpy(rotate_register, ctx->hash, 8 * sizeof(uint32_t));

		// hash calculation loop
		for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
			s0 = rotate_right(rotate_register[0], 2)
			     ^ rotate_right(rotate_register[0], 13)
			     ^ rotate_right(rotate_register[0], 22);
			maj = (rotate_register[0] & rotate_register[1])
			      ^ (rotate_register[0] & rotate_register[2])
			      ^ (rotate_register[1] & rotate_register[2]);
			t2 = s0 + maj;
			s1 = rotate_right(rotate_register[4], 6)
			     ^ rotate_right(rotate_register[4], 11)
			     ^ rotate_right(rotate_register[4], 25);
			ch = (rotate_register[4] & rotate_register[5])
			     ^ (~rotate_register[4] & rotate_register[6]);
			t1 = rotate_register[7] + s1 + ch + k[i] + w_union.w_word[i];

			rotate_register[7] = rotate_register[6];
			rotate_register[6] = rotate_register[5];
			rotate_register[5] = rotate_register[4];
			rotate_register[4] = rotate_register[3] + t1;
			rotate_register[3] = rotate_register[2];
			rotate_register[2] = rotate_register[1];
			rotate_register[1] = rotate_register[0];
			rotate_register[0] = t1 + t2;
		}

		// Add the hash of this block to current result.
		for (i = 0; i < 8; i++)
			ctx->hash[i] += rotate_register[i];
	}
}

/******************************************************************************/
void
vs_hsm_sw_sha256_init(vs_hsm_sw_sha256_ctx* ctx) {
	static const uint32_t hash_init[] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	int i;

	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->hash, hash_init, 8 * sizeof(uint32_t));
}

/******************************************************************************/
void
vs_hsm_sw_sha256_update(vs_hsm_sw_sha256_ctx* ctx, const uint8_t* msg, uint32_t msg_size){
	uint32_t block_count;
	uint32_t rem_size = SHA256_BLOCK_SIZE - ctx->block_size;
	uint32_t copy_size = msg_size > rem_size ? rem_size : msg_size;

	// Copy data into current block
	memcpy(&ctx->block[ctx->block_size], msg, copy_size);

	if (ctx->block_size + msg_size < SHA256_BLOCK_SIZE) {
		// Not enough data to finish off the current block
		ctx->block_size += msg_size;
		return;
	}

	// Process the current block
    _sw_sha256_process(ctx, ctx->block, 1);

	// Process any additional blocks
	msg_size -= copy_size; // Adjust to the remaining message bytes
	block_count = msg_size / SHA256_BLOCK_SIZE;
    _sw_sha256_process(ctx, &msg[copy_size], block_count);

	// Save any remaining data
	ctx->total_msg_size += (block_count + 1) * SHA256_BLOCK_SIZE;
	ctx->block_size = msg_size % SHA256_BLOCK_SIZE;
	memcpy(ctx->block, &msg[copy_size + block_count * SHA256_BLOCK_SIZE], ctx->block_size);
}

/******************************************************************************/
void
vs_hsm_sw_sha256_final(vs_hsm_sw_sha256_ctx* ctx, uint8_t digest[SHA256_DIGEST_SIZE]){
	int i, j;
	uint32_t msg_size_bits;
	uint32_t pad_zero_count;

	// Calculate the total message size in bits
	ctx->total_msg_size += ctx->block_size;
	msg_size_bits = ctx->total_msg_size * 8;

	// Calculate the number of padding zero bytes required between the 1 bit byte and the 64 bit message size in bits.
	pad_zero_count = (SHA256_BLOCK_SIZE - ((ctx->block_size + 9) % SHA256_BLOCK_SIZE)) % SHA256_BLOCK_SIZE;

	// Append a single 1 bit
	ctx->block[ctx->block_size++] = 0x80;

	// Add padding zeros plus upper 4 bytes of total msg size in bits (only supporting 32bit message bit counts)
	memset(&ctx->block[ctx->block_size], 0, pad_zero_count + 4);
	ctx->block_size += pad_zero_count + 4;

	// Add the total message size in bits to the end of the current block. Technically this is
	// supposed to be 8 bytes. This shortcut will reduce the max message size to 536,870,911 bytes.
	ctx->block[ctx->block_size++] = (uint8_t)(msg_size_bits >> 24);
	ctx->block[ctx->block_size++] = (uint8_t)(msg_size_bits >> 16);
	ctx->block[ctx->block_size++] = (uint8_t)(msg_size_bits >> 8);
	ctx->block[ctx->block_size++] = (uint8_t)(msg_size_bits >> 0);

    _sw_sha256_process(ctx, ctx->block, ctx->block_size / SHA256_BLOCK_SIZE);

	// All blocks have been processed.
	// Concatenate the hashes to produce digest, MSB of every hash first.
	// 4 means sizeof(int32_t). This change regarding of PVS warning
	for (i = 0; i < 8; i++) {
        for (j = 4 - 1; j >= 0; j--, ctx->hash[i] >>= 8) {
            digest[i * 4 + j] = ctx->hash[i] & 0xFF;
        }
    }
}