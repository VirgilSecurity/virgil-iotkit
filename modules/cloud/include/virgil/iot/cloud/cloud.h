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
 * Cloud library is used for the goals listed below :
 * - obtaining credentials from thing service
 * - connecting to message bin broker over MQTT and subscribing list of topics
 * - processing received messages over message bin
 * - downloading firmware images and trust list files from cloud storage
 *
 * Virgil IoT SDK provides MQTT implementation based on AWS IoT library
 *
 * \section cloud_usage Cloud Usage
 *
 *  Function #vs_cloud_message_bin_process tries to obtain credentials for connecting to message bin broker from thing service using
 *  #vs_cloud_http_get_func_t and connect to broker using #vs_cloud_mb_connect_subscribe_func_t.
 *  Then it waits for new messages periodically calling #vs_cloud_mb_process_func_t.
 *  User can register own handlers for events about new firmware or trust list by calling
 *  #vs_cloud_message_bin_register_default_handler or custom handler for raw data processing from some topics by calling
 *  #vs_cloud_message_bin_register_custom_handler
 *  Cloud library uses provision and firmware modules, which must be initialized before.
 *
 *  Here you can see an example of Cloud library initialization :
 *
 *  \code
 *
 *  const vs_cloud_impl_t *cloud_impl;                          // Cloud implementation
 *  const vs_cloud_message_bin_impl_t *message_bin_impl;        // Message bin implementation
 *  vs_hsm_impl_t *hsm_impl;                                    // Security module implementation
 *  vs_cloud_mb_process_default_topic_cb_t tl_topic_process;    // Trust List topic processor
 *  vs_cloud_mb_process_default_topic_cb_t fw_topic_process;    // Firmware topic processor
 *  vs_storage_op_ctx_t tl_storage_impl;                        // Trust List storage implementation
 *  vs_storage_op_ctx_t fw_storage_impl;                        // Firmware storage implementation
 *  static vs_device_manufacture_id_t _manufacture_id;          // Manufacture ID
 *  static vs_device_type_t _device_type;                       // Device type
 *
 *  // Provision module
 *  STATUS_CHECK(vs_provision_init(&tl_storage_impl, hsm_impl), "Cannot initialize Provision module");
 *
 *  // Firmware module
 *  STATUS_CHECK(vs_firmware_init(&fw_storage_impl, hsm_impl, manufacture_id, device_type), "Unable to initialize Firmware module");
 *
 *  // Cloud module
 *  STATUS_CHECK(vs_cloud_init(cloud_impl, message_bin_impl, hsm_impl), "Unable to initialize Cloud module");
 *  STATUS_CHECK(vs_cloud_message_bin_register_default_handler(VS_CLOUD_MB_TOPIC_TL, tl_topic_process), "Error register handler for Trust List topic");
 *  STATUS_CHECK(vs_cloud_message_bin_register_default_handler(VS_CLOUD_MB_TOPIC_FW, fw_topic_process), "Error register handler for Firmware topic");
 *
 *  \endcode
 *
 * You can use #vs_curl_http_impl() for \a cloud_impl, #vs_aws_message_bin_impl() for \a message_bin_impl,
 * #vs_softhsm_impl() for \a hsm_impl.
 *
 * \a firmware_topic_process receives URL, where it can fetch a new version of Firmware.
 * See \ref firmware_usage for details.
 *
 * \a tl_topic_process receives URL, where it can fetch a new version of Trust List.
 * See \ref trust_list_usage for Trust List processing details.
 *
 *  Here you can see an example of Cloud library usage:
 *
 *  \code
 *  // Handlers for default topics example
 * void
 * firmware_topic_process(const uint8_t *url, uint16_t length) {
 *      vs_status_e res;
 *      vs_firmware_header_t header;
 *
 *      res = vs_cloud_fetch_and_store_fw_file(url, &header);
 *
 *      if (VS_CODE_OK == res) {
 *          res = vs_firmware_verify_firmware(&header.descriptor);
 *          if (VS_CODE_OK == res) {
 *             // Fetched firmware is correct. Process it
 *          } else {
 *              // Incorrect firmware image. You can delete it.
 *              vs_firmware_delete_firmware(&header.descriptor);
 *          }
 *      }
 *  }
 *
 * void
 * tl_topic_process(const uint8_t *url, uint16_t length) {
 *
 *      if (VS_CODE_OK == vs_cloud_fetch_and_store_tl(url)) {
 *          // Trust list is correct. Process it
 *      }
 *  }
 *
 * // Processing of cloud library functionality example
 * void
 * message_bin_mqtt_task(void *params) {
 *    while (true) {
 *        if (VS_CODE_OK == vs_cloud_message_bin_process()) {
 *            sleep(500);
 *        } else {
 *            sleep(5000);
 *        }
 *     }
 *  }
 * \endcode
 *
 */

#ifndef VS_CLOUD_H
#define VS_CLOUD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <virgil/iot/firmware/firmware.h>
#include <global-hal.h>
#include <virgil/iot/status_code/status_code.h>

#define VS_UPD_URL_STR_SIZE 200

// TODO : contents must be const
/** Callback for data header download
 *
 * This function callback stores loaded handler in internal buffers.
 * 
 * \param[in] contents Input data. Must not be NULL.
 * \param[in] chunksize Input data size. Must not be zero.
 * \param[in,out] userdata Data specific context. Must not be NULL.
 * 
 * \return Loaded data size of #vs_status_e error code
 */
typedef size_t (*vs_fetch_handler_cb_t)(char *contents, size_t chunksize, void *userdata);

// TODO : hander_data ==> handler_data
/** Callback for GET request processing
 *
 * This function callback has to load requested data and to store it in \a out_data output buffer.
 *
 * \param[in] url URL for data download. Must not be NULL.
 * \param[out] out_data Output buffer to store processed data if fetch_handler has not been specified. Must not be NULL.
 * \param[in] fetch_handler Callback to process information that has been downloaded. If NULL, default processing will be used.
 * \param[in] hander_data Context from \a fetch_handler . \a userdata parameter.
 * \param[in,out] in_out_size Data size storage. Must not be NULL.
 * 
 * \return #VS_CODE_OK in case of success or error code.
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

/** Fetch and store Firmware
 *
 * Fetches Firmware and stores it in internal storage.
 *
 * \param[in] fw_file_url Firmware URL to fetch. Must not be NULL.
 * \param[out] fetched_header
 * 
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_fetch_and_store_fw_file(const char *fw_file_url, vs_firmware_header_t *fetched_header);

/** Fetch and store Trust List
 *
 * Fetches Trust List and stores it in internal storage.
 *
 * \param[in] tl_file_url Trust List URL to fetch. Must not be NULL.
 * 
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_fetch_and_store_tl(const char *tl_file_url);

/** List of available topics
 *
 * This structure contains list of topics to be subscribed.
 */
typedef struct {
    char *topic_list;         /**< Text string with all topics */
    uint16_t *topic_len_list; /**< List for each topis size */
    size_t topic_count;       /**< Topics amount for \a topic_list and \a topic_len_list */
} vs_cloud_mb_topics_list_t;

/** Default topics
 *
 * This is the list of default topics processed by #vs_cloud_mb_process_default_topic_cb_t() callback.
 */
typedef enum {
    VS_CLOUD_MB_TOPIC_TL, /**< Trust List */
    VS_CLOUD_MB_TOPIC_FW  /**< Firmware */
} vs_cloud_mb_topic_id_t;

// TODO : rename p_data to data
/** Callback for custom topics processing
 *
 * This callback has to process messages from topics as raw data.
 *
 * \param[in] topic Topic name. Cannot be NULL.
 * \param[in] topic_sz Topic name size. Cannot be zero.
 * \param[in] p_data Topic data. Cannot be NULL
 * \param[in] length Topic data size. Cannot be zero.
 */
typedef void (*vs_cloud_mb_process_custom_topic_cb_t)(const char *topic,
                                                      uint16_t topic_sz,
                                                      const uint8_t *p_data,
                                                      uint16_t length);

/** Callback for default topics processing
 *
 * Virgil IoT SDK preprocesses topics from #vs_cloud_mb_topic_id_t enumeration. It calls this callback when received
 * a notification about a new version of Trust List or Firmware
 * to load data for this topic.
 *
 * \param[in] url URL where from user can fetch a new version of file.
 * \param[in] length Topic URL size.
 */
typedef void (*vs_cloud_mb_process_default_topic_cb_t)(const uint8_t *url, uint16_t length);

/** Register processing handlers for default topics from #vs_cloud_mb_topic_id_t enumeration
 *
 * Registers topic processing handlers.
 *
 * \param[in] topic_id Topic identifier.
 * \param[in] handler Topic processing callback. Must not be NULL.
 * 
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_message_bin_register_default_handler(vs_cloud_mb_topic_id_t topic_id,
                                              vs_cloud_mb_process_default_topic_cb_t handler);

/** Register custom handler callback
 *
 * Registers custom topics processing.
 * You can use #vs_cloud_message_bin_register_default_handler() if it is enough default topics processing.
 *
 * \param[in] handler Custom topics processing handler. Must not be NULL.
 * 
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_message_bin_register_custom_handler(vs_cloud_mb_process_custom_topic_cb_t handler);

/** Message bin initialization
 *
 * This callback must initialize MQTT with specified URL and certificates.
 * #vs_aws_message_bin_impl() returns #vs_cloud_message_bin_impl_t structure with default implementation provided by
 * Virgil IoT SDK library. You can analyze function pointed by \a init member for an example.
 *
 * \param[in] host Host URL. Must not be NULL.
 * \param[in] port Port for host access.
 * \param[in] device_cert Device certificate to be send to the broker.
 * \param[in] priv_key Device private key.
 * \param[in] ca_cert Broker's certificate. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_mb_init_func_t)(const char *host,
                                               uint16_t port,
                                               const char *device_cert,
                                               const char *priv_key,
                                               const char *ca_cert);

/** Message bin connection and topic subscribing implementation
 *
 * This callback must connect to the message bin broker and subscribe topics.
 * #vs_aws_message_bin_impl() returns #vs_cloud_message_bin_impl_t structure with default implementation provided by
 * Virgil IoT SDK library. You can analyze function pointed by \a connect_subscribe member for an example.
 *
 * \param[in] client_id Client identifier. Cannot be NULL.
 * \param[in] login Login. Cannot be NULL.
 * \param[in] password Password. Cannot be NULL.
 * \param[in] topic_list Pointer to the list of topics. Cannot be NULL.
 * \param[in] process_topic Callback for topics processing. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_mb_connect_subscribe_func_t)(const char *client_id,
                                                            const char *login,
                                                            const char *password,
                                                            const vs_cloud_mb_topics_list_t *topic_list,
                                                            vs_cloud_mb_process_custom_topic_cb_t process_topic);

/** Message Bin processing
 *
 * Callback for message bin processing.
 * #vs_aws_message_bin_impl() returns #vs_cloud_message_bin_impl_t structure with default implementation provided by
 * Virgil IoT SDK library. You can analyze function pointed by \a process member for an example.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_mb_process_func_t)(void);

/** Message Bin implementation */
typedef struct {
    vs_cloud_mb_init_func_t init; /**< Message bin initialization */
    vs_cloud_mb_connect_subscribe_func_t connect_subscribe; /**< Message bin connection and topic subscribing */
    vs_cloud_mb_process_func_t process; /**< Message bin processing : listen incoming messages and executing callback calls */
} vs_cloud_message_bin_impl_t;

/** Process message bin
 *
 * Initializes message bin if needed and processes protocol.
 * Normally this function is called in the MQTT processing infinite loop.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_message_bin_process(void);

/** Initialize message bin
 *
 * \param[in] cloud_impl Cloud implementation. Must not be NULL.
 * \param[in] message_bin_impl Message bin implementation. You can use default implementation returned by #vs_aws_message_bin_impl(). Must not be NULL.
 * \param[in] hsm Security module implementation. You can use default implementation returned by #vs_softhsm_impl(). Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_init(const vs_cloud_impl_t *cloud_impl,
              const vs_cloud_message_bin_impl_t *message_bin_impl,
              vs_hsm_impl_t *hsm);

#endif // VS_CLOUD_H
