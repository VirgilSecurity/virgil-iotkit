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

typedef struct {
    char *topic_list;
    uint16_t *topic_len_list;
    size_t topic_count;
} vs_cloud_mb_topics_list_t;

typedef struct {
    char *login;
    char *password;
    char *cert;
    char *pk;
    char *host;
    vs_cloud_mb_topics_list_t topic_list;
    char *client_id;
    uint16_t port;
    bool is_filled;
    bool is_active;
} vs_cloud_mb_mqtt_ctx_t;

typedef enum {
    VS_CLOUD_ERR_OK,
    VS_CLOUD_ERR_FAIL,
    VS_CLOUD_ERR_INVAL,        // invalid parameters
    VS_CLOUD_ERR_NOMEM,        // out of memory
    VS_CLOUD_ERR_DECRYPT_FAIL, //
    VS_CLOUD_ERR_VALUE_FAIL,   //
    VS_CLOUD_ERR_NOT_FOUND,
} vs_cloud_err_code_e;

#define VS_UPD_URL_STR_SIZE 200

#define HTTPS_RET_CODE_ERROR_OPEN_SESSION 1000
#define HTTPS_RET_CODE_ERROR_PREPARE_REQ 1001
#define HTTPS_RET_CODE_ERROR_SEND_REQ 1002
#define HTTPS_RET_CODE_ERROR_GET 1003
#define HTTPS_RET_CODE_OK 200

/* Request methods */
typedef enum {
    VS_HTTP_OPTIONS, /* request to server for communication  options */
    VS_HTTP_GET,     /* retrieve information */
    VS_HTTP_HEAD,    /* get meta-info */
    VS_HTTP_POST,    /* request to accept new sub-ordinate of resource */
    VS_HTTP_PUT,     /* modify or create new resource referred to by URI */
    VS_HTTP_PATCH,   /* modify or create new resource referred
                      * to by URI */
    VS_HTTP_DELETE,  /* delete the resource */
    VS_HTTP_TRACE,   /* echo */
    VS_HTTP_CONNECT, /* do we need this  ? */
} vs_http_method_t;

typedef struct __attribute__((__packed__)) {
    uint32_t code_offset;   // sizeof(vs_cloud_firmware_header_t)
    uint32_t code_length;   // firmware_length
    uint32_t footer_offset; // code_offset + code_length
    uint32_t footer_length;
    uint8_t signatures_count;
    vs_firmware_descriptor_t descriptor;
} vs_cloud_firmware_header_t;

typedef int (*vs_cloud_mb_init_func)(const char *host,
                                     uint16_t port,
                                     const char *device_cert,
                                     const char *priv_key,
                                     const char *ca_cert);
typedef int (*vs_cloud_mb_connect_subscribe_func)(const char *client_id,
                                                  const char *login,
                                                  const char *password,
                                                  const vs_cloud_mb_topics_list_t *topic_list);
typedef int (*vs_cloud_mb_process_func)(void);

int
vs_cloud_mb_init_ctx(vs_cloud_mb_mqtt_ctx_t *ctx);

int
vs_cloud_mb_process(vs_cloud_mb_mqtt_ctx_t *ctx,
                    const char *root_ca_crt,
                    vs_cloud_mb_init_func init,
                    vs_cloud_mb_connect_subscribe_func connect_subscribe,
                    vs_cloud_mb_process_func process);

typedef size_t (*vs_fetch_handler_func_t)(char *contents, size_t chunksize, void *userdata);

int
vs_cloud_parse_firmware_manifest(const vs_storage_op_ctx_t *fw_storage,
                                 void *payload,
                                 size_t payload_len,
                                 char *fw_url);

int
vs_cloud_parse_tl_mainfest(void *payload, size_t payload_len, char *tl_url);

int
vs_cloud_fetch_and_store_fw_file(const vs_storage_op_ctx_t *fw_storage,
                                 const char *fw_file_url,
                                 vs_cloud_firmware_header_t *fetched_header);

int
vs_cloud_fetch_and_store_tl(const char *tl_file_url);

#endif // VS_CLOUD_H
