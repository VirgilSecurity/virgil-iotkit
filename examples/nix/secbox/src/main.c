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

#include <nix-file-io.h>

#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/secbox/secbox.h>
#include <nix-storage-impl.h>

#define MAX_FILE_SIZE   1024
#define FILE_DIR        "secbox-example"

/******************************************************************************/
int main(int argc, char *argv[]){
    vs_storage_op_ctx_t secbox_ctx;
    vs_storage_element_id_t file_id;
    const char *filename = "filename.txt";
    const uint8_t data_src[] = "Some text";
    uint8_t data_dst[sizeof(data_src)];
    uint16_t hash_sz;
    vs_status_e ret_code;
    size_t data_size = sizeof(data_src);

    // Initialize logger
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Initialize storage context
    vs_hal_files_set_dir(FILE_DIR);

    vs_nix_get_storage_impl(&secbox_ctx.impl);
    secbox_ctx.file_sz_limit = MAX_FILE_SIZE;
    secbox_ctx.storage_ctx = vs_nix_storage_init(vs_nix_get_secbox_dir());

    // Erase OTP provision
    STATUS_CHECK_RET(vs_hsm_slot_delete(PRIVATE_KEY_SLOT), "Unable to erase private key slot");
    STATUS_CHECK_RET(vs_hsm_slot_delete(REC1_KEY_SLOT), "Unable to erase REC1 key slot");
    STATUS_CHECK_RET(vs_hsm_slot_delete(REC2_KEY_SLOT), "Unable to erase REC2 key slot");

    // Create device key
    STATUS_CHECK_RET(vs_hsm_keypair_create(PRIVATE_KEY_SLOT, VS_KEYPAIR_EC_SECP256R1), "Unable to create device's key");

    // Initialize secbox
    STATUS_CHECK_RET(vs_secbox_init(&secbox_ctx), "Unable to initialize secbox");

    // Calculate hash for file name
    // TODO : hash is not necessary, remove it
    STATUS_CHECK_RET(vs_hsm_hash_create(VS_HASH_SHA_256, (uint8_t *)filename, strlen(filename), file_id, sizeof(file_id), &hash_sz),
    "Unable to calculate hash for file name %s", filename);

    // Remove data
    STATUS_CHECK_RET(vs_secbox_del(&secbox_ctx, file_id), "Unable to delete data");

    // Save signed and encrypted data
    STATUS_CHECK_RET(vs_secbox_save(&secbox_ctx, VS_SECBOX_SIGNED_AND_ENCRYPTED, file_id, data_src, data_size), "Unable to save signed data");

    // Check file size
    assert(data_size == vs_secbox_file_size(&secbox_ctx, file_id));

    // Load signed and encrypted data
    STATUS_CHECK_RET(vs_secbox_load(&secbox_ctx, file_id, data_dst, data_size), "Unable to load signed data");

    // Compare source and loaded datas
    CHECK_RET(!memcmp(data_src, data_dst, data_size), VS_CODE_ERR_FILE, "Save/load data mismatch");

    // Free resource
    vs_secbox_deinit(&secbox_ctx);

    return 0;
}