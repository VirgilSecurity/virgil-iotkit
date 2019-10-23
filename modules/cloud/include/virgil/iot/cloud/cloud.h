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

// TODO : finish description !!!
/*! \file cloud.h
 * \brief Cloud implementation
 *
 * креды для работы с MQTT thing service
 * подключение к MQTT с помощью кредов
 * скачивание trust list, firmware
 * пример работы
 * topics list - vs_cloud_mb_topic_id_t
 */

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

// TODO : contents must be const
/** Callback for download file parts
 * 
 * \param[in] contents Input data. Must not be NULL.
 * \param[in] chunksize Input data size. Must not be zero.
 * \param[in,out] userdata Data context. Must not be NULL.
 * 
 * \return
 */
typedef size_t (*vs_fetch_handler_cb_t)(char *contents, size_t chunksize, void *userdata);

// TODO : hander_data ==> handler_data
// TODO : it looks like hander_data is for CURL call
/** Callback for GET request processing
 * 
 * \param[in] url URL for data download. Must not be NULL.
 * \param[out] out_data Output buffer to store processed data if fetch_handler has not been specified. Must not be NULL.
 * \param[in] fetch_handler Callback to process information that has been downloaded. If NULL, default processing will be used.
 * \param[in] hander_data Context from \a fetch_handler \a userdata parameter.
 * \param[in,out] in_out_size Data size storage. Must not be NULL.
 * 
 * \return \ref VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_http_get_func_t)(const char *url,
                                                char *out_data,
                                                vs_fetch_handler_cb_t fetch_handler,
                                                void *hander_data,
                                                size_t *in_out_size);

/** Cloud implementation */
typedef struct {
    vs_cloud_http_get_func_t http_get; /**< Callback for GET request processing */
} vs_cloud_impl_t;

/** Parse Firmware manifest obtained by MQTT
 *
 * Parse Firmware manifest obtained by MQTT and return URL for Firmware download.
 *
 * \param[in] payload 
 * \param[in] payload_len 
 * \param[out] fw_url Buffer for Firmware download URL. Must be enough to store \ref VS_UPD_URL_STR_SIZE bytes. Must not be NULL.
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */

vs_status_e
vs_cloud_parse_firmware_manifest(void *payload, size_t payload_len, char *fw_url);

/** Parse Trust List manifest obtained by MQTT
 *
 * Parse Trust List manifest obtained by MQTT and return URL for Firmware download.
 *
 * \param[in] payload
 * \param[in] payload_len
 * \param[out] tl_url Buffer for Trust List download URL. Must be enough to store \ref VS_UPD_URL_STR_SIZE bytes. Must not be NULL.
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */

vs_status_e
vs_cloud_parse_tl_mainfest(void *payload, size_t payload_len, char *tl_url);

/** Load and store Firmware File
 *
 * \param[in] fw_file_url 
 * \param[out] fetched_header
 * 
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_fetch_and_store_fw_file(const char *fw_file_url, vs_firmware_header_t *fetched_header);

/**
 * 
 * \param[in] tl_file_url 
 * 
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_fetch_and_store_tl(const char *tl_file_url);

/** List of available topics
 *
 * Used for MQTT.
 */
typedef struct {
    char *topic_list; /**< Text string with all topics */
    uint16_t *topic_len_list; /**< List for each topis size */
    size_t topic_count; /**< Topics amount for \a topic_list and \a topic_len_list */
} vs_cloud_mb_topics_list_t;

/** Default topics */
typedef enum {
    VS_CLOUD_MB_TOPIC_TL, /**< Trust List */
    VS_CLOUD_MB_TOPIC_FW /**< Firmware */
}vs_cloud_mb_topic_id_t;

// TODO : rename p_data to data
/** Callback for custom processing of topics
 *
 * This function processes raw topic data
 *
 * \param[in] topic Topic name. Cannot be NULL.
 * \param[in] topic_sz Topic name size. Cannot be zero.
 * \param[in] p_data Topic data.
 * \param[in] length Topic data size.
 */
typedef void (*vs_cloud_mb_process_custom_topic_cb_t)(const char *topic,
                                               uint16_t topic_sz,
                                               const uint8_t *p_data,
                                               uint16_t length);

/** Callback for default processing of topics
 *
 * This function receives topic URL
 *
 * \param[in] url Topic URL.
 * \param[in] length Topic URL size.
 */
typedef void (*vs_cloud_mb_process_default_topic_cb_t)(const uint8_t *url,
                                                      uint16_t length);

/** Register default processing for topic
 * 
 * \param[in] topic_id 
 * \param[in] handler 
 * 
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_message_bin_register_default_handler(vs_cloud_mb_topic_id_t topic_id, vs_cloud_mb_process_default_topic_cb_t handler);

/** Register custom handler callback
 *
 * This callback is used for topics that have not been registered by \ref vs_cloud_message_bin_register_default_handler
 *
 * \param[in] handler 
 * 
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_message_bin_register_custom_handler(vs_cloud_mb_process_custom_topic_cb_t handler);

/** Message Bin initialization
 * 
 * \param[in] host 
 * \param[in] port 
 * \param[in] device_cert Device certificate to be send to broker.
 * \param[in] priv_key 
 * \param[in] ca_cert Broker's certificate. Must not be NULL.
 * 
 * \return \ref VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_mb_init_func_t)(const char *host,
                                               uint16_t port,
                                               const char *device_cert,
                                               const char *priv_key,
                                               const char *ca_cert);

/** Message Bin connection
 * \param[in] client_id
 * \param[in] login
 * \param[in] password
 * \param[in] topic_list
 * \param[in] process_topic
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_mb_connect_subscribe_func_t)(const char *client_id,
                                                            const char *login,
                                                            const char *password,
                                                            const vs_cloud_mb_topics_list_t *topic_list,
                                                            vs_cloud_mb_process_custom_topic_cb_t process_topic);

/** Message Bin processing
 * 
 * \return \ref VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_mb_process_func_t)(void);

typedef struct {
    vs_cloud_mb_init_func_t init; /**< */
    vs_cloud_mb_connect_subscribe_func_t connect_subscribe; /**< */
    vs_cloud_mb_process_func_t process; /**< */
} vs_cloud_message_bin_impl_t;

/** Process Message Bin
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_message_bin_process(void);

/** Initialize Message Bin
 *
 * \param[in] cloud_impl Cloud implementation. Must not be NULL.
 * \param[in] message_bin_impl Message bin implementation. Must not be NULL.
 * \param[in] hsm HSM implementation. Must not be NULL.
 *
 * \return \ref VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_init(const vs_cloud_impl_t *cloud_impl,
              const vs_cloud_message_bin_impl_t *message_bin_impl,
              vs_hsm_impl_t *hsm);

#endif // VS_CLOUD_H
