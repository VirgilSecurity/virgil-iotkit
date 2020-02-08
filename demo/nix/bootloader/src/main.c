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

#include <errno.h>
#include <unistd.h>

#include <helpers/app-helpers.h>
#include <helpers/app-storage.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/vs-soft-secmodule/vs-soft-secmodule.h>

#include <trust_list-config.h>
#include <update-config.h>

// Device parameters
static vs_device_manufacture_id_t _manufacture_id;
static vs_device_type_t _device_type;
static const vs_key_type_e sign_rules_list[VS_FW_SIGNATURES_QTY] = VS_FW_SIGNER_TYPE_LIST;
static char *_path_to_image = NULL;
static vs_secmodule_impl_t *_secmodule_impl = NULL;

/******************************************************************************/
static ssize_t
_boot_get_image_size(void) {
    FILE *fp = NULL;
    ssize_t res = -1;

    assert(_path_to_image);
    CHECK_NOT_ZERO_RET(_path_to_image, VS_CODE_ERR_FILE_READ);

    fp = fopen(_path_to_image, "rb");

    if (fp) {

        CHECK(0 == fseek(fp, 0, SEEK_END), "fseek error errno = %d (%s)", errno, strerror(errno));

        res = ftell(fp);

        if (res <= 0) {
            VS_LOG_ERROR("Unable to prepare file %s to read. errno = %d (%s)", _path_to_image, errno, strerror(errno));
            res = -1;
            goto terminate;
        }
    } else {
        VS_LOG_WARNING("Unable to open file %s. errno = %d (%s)", _path_to_image, errno, strerror(errno));
    }

terminate:
    if (fp) {
        fclose(fp);
    }
    return res;
}

/******************************************************************************/
static vs_status_e
_boot_load_image_chunk(uint32_t offset, uint8_t *data, size_t buf_sz, size_t *read_sz) {
    FILE *fp = NULL;
    int64_t max_avail_sz;
    vs_status_e res = VS_CODE_ERR_FILE_READ;

    assert(_path_to_image);
    CHECK_NOT_ZERO_RET(_path_to_image, VS_CODE_ERR_FILE_READ);

    fp = fopen(_path_to_image, "rb");

    if (fp) {
        CHECK(0 == fseek(fp, offset, SEEK_END), "fseek error errno = %d (%s)", errno, strerror(errno));

        max_avail_sz = ftell(fp) - offset;

        if (max_avail_sz < 0) {
            VS_LOG_ERROR("File %s is smaller than offset %u", buf_sz, _path_to_image, offset);
            *read_sz = 0;
            goto terminate;
        }

        CHECK(0 == fseek(fp, offset, SEEK_SET), "fseek error errno = %d (%s)", errno, strerror(errno));

        *read_sz = max_avail_sz < buf_sz ? max_avail_sz : buf_sz;

        VS_LOG_DEBUG("Read file '%s', %d bytes", _path_to_image, (int)*read_sz);

        if (1 == fread((void *)data, *read_sz, 1, fp)) {
            res = VS_CODE_OK;
        } else {
            VS_LOG_ERROR("Unable to read %d bytes from %s", *read_sz, _path_to_image);
            *read_sz = 0;
        }

    } else {
        VS_LOG_ERROR("Unable to open file %s. errno = %d (%s)", _path_to_image, errno, strerror(errno));
    }

terminate:

    if (fp) {
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
static bool
_is_rule_equal_to(vs_key_type_e type) {
    uint8_t i;
    for (i = 0; i < VS_FW_SIGNATURES_QTY; ++i) {
        if (sign_rules_list[i] == type) {
            return true;
        }
    }
    return false;
}


/*************************************************************************/
vs_status_e
vs_firmware_self_verify(void) {

    ssize_t file_sz;
    uint8_t sign_rules = 0;
    uint16_t i;
    vs_secmodule_sw_sha256_ctx hash_ctx;
    vs_status_e ret_code;
    size_t read_sz;


    // TODO: Need to support all hash types
    uint8_t hash[VS_HASH_SHA256_LEN];

    int footer_sz = vs_firmware_get_expected_footer_len();
    CHECK_RET(footer_sz > 0, VS_CODE_ERR_INCORRECT_ARGUMENT, "Can't get footer size");
    uint8_t footer_buf[footer_sz];

    file_sz = _boot_get_image_size();
    CHECK_RET(file_sz > 0 && file_sz > footer_sz, VS_CODE_ERR_FILE, "Wrong self file format");

    STATUS_CHECK_RET(_boot_load_image_chunk(file_sz - footer_sz, footer_buf, footer_sz, &read_sz),
                     "Can't read self footer");


    vs_firmware_footer_t *footer = (vs_firmware_footer_t *)footer_buf;
    vs_firmware_descriptor_t desc;
    memcpy(&desc, &footer->descriptor, sizeof(vs_firmware_descriptor_t));
    vs_firmware_ntoh_descriptor(&desc);

    CHECK_RET(footer_sz <= file_sz - desc.firmware_length, VS_CODE_ERR_FILE, "Incorrect footer size");
    CHECK_RET(0 == VS_IOT_MEMCMP(desc.info.device_type, _device_type, sizeof(vs_device_type_t)),
              VS_CODE_ERR_FILE,
              "Incorred manufacture id");
    CHECK_RET(0 == VS_IOT_MEMCMP(desc.info.manufacture_id, _manufacture_id, sizeof(vs_device_manufacture_id_t)),
              VS_CODE_ERR_FILE,
              "Incorred device type");

    uint8_t buf[desc.chunk_size];
    uint32_t offset = 0;

    _secmodule_impl->hash_init(&hash_ctx);

    // Update hash by firmware
    while (offset < file_sz - footer_sz) {
        uint32_t fw_rest = file_sz - footer_sz - offset;
        uint32_t required_chunk_size = fw_rest > desc.chunk_size ? desc.chunk_size : fw_rest;

        STATUS_CHECK_RET(_boot_load_image_chunk(offset, buf, required_chunk_size, &read_sz),
                         "Error read firmware chunk");

        _secmodule_impl->hash_update(&hash_ctx, buf, required_chunk_size);
        offset += required_chunk_size;
    }

    // Update hash by footer
    _secmodule_impl->hash_update(&hash_ctx, footer_buf, sizeof(vs_firmware_footer_t));
    _secmodule_impl->hash_finish(&hash_ctx, hash);

    // First signature
    vs_sign_t *sign = (vs_sign_t *)footer->signatures;

    CHECK_RET(footer->signatures_count >= VS_FW_SIGNATURES_QTY, VS_CODE_ERR_FILE, "There are not enough signatures");

    for (i = 0; i < footer->signatures_count; ++i) {
        uint8_t *pubkey;
        int sign_len;
        int key_len;

        CHECK_RET(sign->hash_type == VS_HASH_SHA_256, VS_CODE_ERR_UNSUPPORTED, "Unsupported hash size for sign FW");

        sign_len = vs_secmodule_get_signature_len(sign->ec_type);
        key_len = vs_secmodule_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_CODE_ERR_UNSUPPORTED, "Unsupported signature ec_type");

        // Signer raw key pointer
        pubkey = sign->raw_sign_pubkey + (uint16_t)sign_len;

        STATUS_CHECK_RET(vs_provision_search_hl_pubkey(sign->signer_type, sign->ec_type, pubkey, (uint16_t)key_len),
                         "Signer key is wrong");

        if (_is_rule_equal_to(sign->signer_type)) {
            STATUS_CHECK_RET(_secmodule_impl->ecdsa_verify(sign->ec_type,
                                                           pubkey,
                                                           (uint16_t)key_len,
                                                           sign->hash_type,
                                                           hash,
                                                           sign->raw_sign_pubkey,
                                                           (uint16_t)sign_len),
                             "Signature is wrong");
            sign_rules++;
        }

        // Next signature
        sign = (vs_sign_t *)(pubkey + (uint16_t)key_len);
    }

    VS_LOG_INFO("Self image. Sign rules is %s", sign_rules >= VS_FW_SIGNATURES_QTY ? "correct" : "wrong");

    return sign_rules >= VS_FW_SIGNATURES_QTY ? VS_CODE_OK : VS_CODE_ERR_VERIFY;
}

/******************************************************************************/
static void
_start_app_image(int argc, char *argv[]) {
    const char *MAC_SHORT = "-m";
    const char *MAC_FULL = "--mac";
    char *mac_str = vs_app_get_commandline_arg(argc, argv, MAC_SHORT, MAC_FULL);

    VS_LOG_INFO("Start new app image ...");
    if (-1 == execl(_path_to_image, _path_to_image, MAC_SHORT, mac_str, NULL)) {
        VS_LOG_ERROR("Error start new app. errno = %d (%s)", errno, strerror(errno));
    }
}

/******************************************************************************/
int
main(int argc, char *argv[]) {
    vs_mac_addr_t forced_mac_addr;
    bool is_image_correct = false;
    vs_provision_events_t provision_events = {NULL};

    // Implementation variables
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t slots_storage_impl;

    // Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Get input parameters
    STATUS_CHECK(vs_app_get_mac_from_commandline_params(argc, argv, &forced_mac_addr), "Cannot read input parameters");

    // Get input parameters
    STATUS_CHECK(vs_app_get_image_path_from_commandline_params(argc, argv, &_path_to_image),
                 "Cannot read input parameters");
#if GATEWAY
    const char *title = "Gateway bootloader";
    const char *devices_dir = "gateway";
#else
    const char *title = "Thing bootloader";
    const char *devices_dir = "thing";
#endif
    // Print title
    vs_app_print_title(title, argv[0], MANUFACTURE_ID, DEVICE_MODEL);

    // Prepare local storage
    STATUS_CHECK(vs_app_prepare_storage(devices_dir, forced_mac_addr), "Cannot prepare storage");

    vs_app_str_to_bytes(_manufacture_id, MANUFACTURE_ID, VS_DEVICE_MANUFACTURE_ID_SIZE);
    vs_app_str_to_bytes(_device_type, DEVICE_MODEL, VS_DEVICE_TYPE_SIZE);

    //
    // ---------- Create implementations ----------
    //

    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(vs_app_storage_init_impl(&slots_storage_impl, vs_app_slots_dir(), VS_SLOTS_STORAGE_MAX_SIZE),
                 "Cannot create TrustList storage");

    // Soft Security Module
    _secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

    //
    // ---------- Initialize Virgil SDK modules ----------
    //

    // Provision module
    STATUS_CHECK(vs_provision_init(&tl_storage_impl, _secmodule_impl, provision_events),
                 "Cannot initialize Provision module");

    //
    // ---------- Check firmware image ----------
    //

    STATUS_CHECK(vs_firmware_self_verify(), "Verifying image fail");
    is_image_correct = true;

terminate:

    // Deinit provision
    vs_provision_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();

    if (is_image_correct) {
        _start_app_image(argc, argv);
    }


    VS_LOG_INFO("\n\n\n");
    VS_LOG_INFO("Terminating bootloader ...");
}