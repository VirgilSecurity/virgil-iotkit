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

#ifndef VS_CLOUD_H
#define VS_CLOUD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <virgil/iot/firmware/firmware.h>
#include <global-hal.h>
#include <virgil/iot/status_code/status_code.h>

/*
 *
 * Cloud
 *
 */

#define VS_UPD_URL_STR_SIZE 200

typedef size_t (*vs_fetch_handler_cb_t)(char *contents, size_t chunksize, void *userdata);

typedef vs_status_e (*vs_cloud_http_get_func_t)(const char *url,
                                                char *out_data,
                                                vs_fetch_handler_cb_t fetch_handler,
                                                void *hander_data,
                                                size_t *in_out_size);
typedef struct {
    vs_cloud_http_get_func_t http_get;
} vs_cloud_impl_t;

typedef struct __attribute__((__packed__)) {
    uint32_t code_offset;   // sizeof(vs_cloud_firmware_header_t)
    uint32_t code_length;   // firmware_length
    uint32_t footer_offset; // code_offset + code_length
    uint32_t footer_length;
    uint8_t signatures_count;
    vs_firmware_descriptor_t descriptor;
} vs_cloud_firmware_header_t;

vs_status_e
vs_cloud_parse_firmware_manifest(const vs_storage_op_ctx_t *fw_storage,
                                 void *payload,
                                 size_t payload_len,
                                 char *fw_url);

vs_status_e
vs_cloud_parse_tl_mainfest(void *payload, size_t payload_len, char *tl_url);

vs_status_e
vs_cloud_fetch_and_store_fw_file(const vs_storage_op_ctx_t *fw_storage,
                                 const char *fw_file_url,
                                 vs_cloud_firmware_header_t *fetched_header);

vs_status_e
vs_cloud_fetch_and_store_tl(const char *tl_file_url);

/*
 *
 * Message bin
 *
 */

typedef struct {
    char *topic_list;
    uint16_t *topic_len_list;
    size_t topic_count;
} vs_cloud_mb_topics_list_t;

typedef void (*vs_clud_mb_process_topic_cb_t)(const char *topic,
                                              uint16_t topic_sz,
                                              const uint8_t *p_data,
                                              uint16_t length);

typedef vs_status_e (*vs_cloud_mb_init_func_t)(const char *host,
                                               uint16_t port,
                                               const char *device_cert,
                                               const char *priv_key,
                                               const char *ca_cert);

typedef vs_status_e (*vs_cloud_mb_connect_subscribe_func_t)(const char *client_id,
                                                            const char *login,
                                                            const char *password,
                                                            const vs_cloud_mb_topics_list_t *topic_list,
                                                            vs_clud_mb_process_topic_cb_t process_topic);
typedef vs_status_e (*vs_cloud_mb_process_func_t)(void);

typedef struct {
    vs_cloud_mb_init_func_t init;
    vs_cloud_mb_connect_subscribe_func_t connect_subscribe;
    vs_cloud_mb_process_func_t process;
} vs_cloud_message_bin_impl_t;

vs_status_e
vs_cloud_init(const vs_cloud_impl_t *cloud_impl, const vs_cloud_message_bin_impl_t *message_bin_impl);

vs_status_e
vs_cloud_message_bin_process(vs_clud_mb_process_topic_cb_t process_topic,
                             const char *root_ca_crt);

#endif // VS_CLOUD_H
