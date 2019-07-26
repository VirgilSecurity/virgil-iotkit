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

#ifndef CLOUD_H
#define CLOUD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

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
} vs_cloud_err_code_e;

#define HTTPS_RET_CODE_ERROR_OPEN_SESSION 1000
#define HTTPS_RET_CODE_ERROR_PREPARE_REQ 1001
#define HTTPS_RET_CODE_ERROR_SEND_REQ 1002
#define HTTPS_RET_CODE_ERROR_GET 1003
#define HTTPS_RET_CODE_OK 200

typedef int http_session_t;

/* Request methods */
typedef enum {
    HTTP_OPTIONS, /* request to server for communication  options */
    HTTP_GET,     /* retrieve information */
    HTTP_HEAD,    /* get meta-info */
    HTTP_POST,    /* request to accept new sub-ordinate of resource */
    HTTP_PUT,     /* modify or create new resource referred to by URI */
    HTTP_PATCH,   /* modify or create new resource referred
                   * to by URI */
    HTTP_DELETE,  /* delete the resource */
    HTTP_TRACE,   /* echo */
    HTTP_CONNECT, /* do we need this  ? */
} http_method_t;

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
vs_cloud_fetch_amazon_credentials(char *out_answer, size_t *in_out_answer_len);

int
vs_cloud_fetch_message_bin_credentials(char *out_answer, size_t *in_out_answer_len);

int
vs_cloud_mb_init_ctx(vs_cloud_mb_mqtt_ctx_t *ctx);

int
vs_cloud_mb_process(vs_cloud_mb_mqtt_ctx_t *ctx,
                    const char *root_ca_crt,
                    vs_cloud_mb_init_func init,
                    vs_cloud_mb_connect_subscribe_func connect_subscribe,
                    vs_cloud_mb_process_func process);
#endif // CLOUD_H
