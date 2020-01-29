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

/*! \file cloud.h
 * \brief Cloud implementation
 *
 * Cloud is a library that implements functions for communication with the Cloud and is used for the following :
 * - obtaining credentials from thing service
 * - connecting to message bin broker over MQTT and subscribing to the list of topics
 * - processing messages received over message bin
 * - downloading firmware binaries and trust list files from cloud storage
 *
 * Virgil IoT KIT provides MQTT implementation based on AWS IoT library.
 *
 * \section cloud_usage Cloud Usage
 *
 * Function #vs_cloud_message_bin_process tries to obtain credentials for connecting to message bin broker from thing
 * service using #vs_cloud_http_request_func_t and connect to the broker using #vs_cloud_mb_connect_subscribe_func_t.
 * Then it waits for new messages, periodically calling #vs_cloud_mb_process_func_t. User can register own handlers for
 * events of new firmware or trust list by calling #vs_cloud_message_bin_register_default_handler or custom handler for
 * raw data processing from some topics by calling #vs_cloud_message_bin_register_custom_handler. Cloud module uses
 * provision and firmware modules, which must be initialized before.
 *
 * \note #vs_cloud_init requires #vs_cloud_impl_t, #vs_cloud_message_bin_impl_t and #vs_secmodule_impl_t
implementations.
 * You can provide yours or use standard ones : #vs_curl_http_impl() that uses cURL HTTP, #vs_aws_message_bin_impl()
that
 * implements MQTT, #vs_soft_secmodule_impl() that returns software security module implementation.
 *
 *  Here you can see an example of Cloud module initialization :
 *
 *  \code

const vs_cloud_impl_t *cloud_impl;                          // Cloud implementation
const vs_cloud_message_bin_impl_t *message_bin_impl;        // Message bin implementation
vs_secmodule_impl_t *secmodule_impl;                        // Security module implementation
vs_cloud_mb_process_default_topic_cb_t tl_topic_process;    // Trust List topic processor
vs_cloud_mb_process_default_topic_cb_t fw_topic_process;    // Firmware topic processor
vs_storage_op_ctx_t tl_storage_impl;                        // Trust List storage implementation
vs_storage_op_ctx_t fw_storage_impl;                        // Firmware storage implementation
static vs_device_manufacture_id_t manufacture_id;           // Manufacture ID
static vs_device_type_t device_type;                        // Device type

// Initialize secmodule_impl, cloud_impl, message_bin_impl, tl_storage_impl, fw_storage_impl,
// manufacture_id, device_type

// Provision module
STATUS_CHECK(vs_provision_init(&tl_storage_impl, secmodule_impl), "Cannot initialize Provision module");

// Firmware module
STATUS_CHECK(vs_firmware_init(&fw_storage_impl, secmodule_impl, manufacture_id, device_type), "Unable to initialize
Firmware module");

// Cloud module
STATUS_CHECK(vs_cloud_init(cloud_impl, message_bin_impl, secmodule_impl), "Unable to initialize Cloud module");
STATUS_CHECK(vs_cloud_message_bin_register_default_handler(VS_CLOUD_MB_TOPIC_TL, tl_topic_process),
    "Error register handler for Trust List topic");

STATUS_CHECK(vs_cloud_message_bin_register_default_handler(VS_CLOUD_MB_TOPIC_FW, fw_topic_process), "Error register
handler for Firmware topic");

 *  \endcode
 *
 * You can use #vs_curl_http_impl() for \a cloud_impl, #vs_aws_message_bin_impl() for \a message_bin_impl,
 * #vs_soft_secmodule_impl() for \a secmodule_impl.
 *
 * \a fw_topic_process receives an URL that can be used to fetch a new version of Firmware.
 * See \ref firmware_usage for details.
 *
 *  Here you can see an example of Cloud library usage:
 *
 *  \code
// Processing of cloud library functionality example
void
message_bin_mqtt_task(void *params) {
   while (true) {
       if (VS_CODE_OK == vs_cloud_message_bin_process()) {
           sleep(500);
       } else {
           sleep(5000);
       }
    }
 }

// Handlers for default topics example
void
fw_topic_process(const uint8_t *url, uint16_t length) {
     vs_status_e res;
     vs_firmware_header_t header;

     res = vs_cloud_fetch_and_store_fw_file(url, &header);

     if (VS_CODE_OK == res) {
         res = vs_firmware_verify_firmware(&header.descriptor);
         if (VS_CODE_OK == res) {
            // Fetched firmware is correct. Process it
         } else {
             // Incorrect firmware image. You can delete it.
             vs_firmware_delete_firmware(&header.descriptor);
         }
     }
 }

void
tl_topic_process(const uint8_t *url, uint16_t length) {

     if (VS_CODE_OK == vs_cloud_fetch_and_store_tl(url)) {
         // Trust list is correct. Process it
     }
 }

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

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Length of the update URL string */
#define VS_UPD_URL_STR_SIZE 200

/** Implementation for data header download
 *
 * This function implementation stores loaded handler in internal buffers.
 *
 * \param[in] contents Input data. Must not be NULL.
 * \param[in] chunksize Input data size. Must not be zero.
 * \param[in,out] userdata Data specific context. Must not be NULL.
 *
 * \return Loaded data size of #vs_status_e error code
 */
typedef size_t (*vs_fetch_handler_cb_t)(const char *contents, size_t chunksize, void *userdata);

typedef enum {
    VS_CLOUD_REQUEST_GET, /**< HTTP request by GET method */
    VS_CLOUD_REQUEST_POST /**< HTTP request by POST method */
} vs_cloud_http_method_e;

/** Implementation for GET and POST requests processing
 *
 * This function implementation loads requested data and stores it in the \a out_data output buffer.
 *
 * \param[in] method HTTP method, which will be performed
 * \param[in] url URL for data download. Must not be NULL.
 * \param[in] request_body The body of the POST request.
 * \param[in] request_body_size The size of the POST request body.
 * \param[out] out_data Output buffer to store processed data if fetch_handler has not been specified. Must not be NULL.
 * \param[in] fetch_handler Implementation to process information that has been downloaded. If NULL, default processing
 * will be used. \param[in] fetch_hander_data Context from \a fetch_handler . \a userdata parameter. \param[in,out]
 * in_out_size Data size storage. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_http_request_func_t)(vs_cloud_http_method_e method,
                                                    const char *url,
                                                    const char *request_body,
                                                    size_t request_body_size,
                                                    char *out_data,
                                                    vs_fetch_handler_cb_t fetch_handler,
                                                    void *hander_data,
                                                    size_t *in_out_size);

/** Cloud implementation */
typedef struct {
    vs_cloud_http_request_func_t http_request; /**< GET and POST requests processing */
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
 * This is the list of default topics processed by #vs_cloud_mb_process_default_topic_cb_t() implementation.
 */
typedef enum {
    VS_CLOUD_MB_TOPIC_TL, /**< Trust List */
    VS_CLOUD_MB_TOPIC_FW  /**< Firmware */
} vs_cloud_mb_topic_id_t;

/** Implementation for custom topics processing
 *
 * This implementation processes messages from topics as raw data.
 *
 * \param[in] topic Topic name. Cannot be NULL.
 * \param[in] topic_sz Topic name size. Cannot be zero.
 * \param[in] data Topic data. Cannot be NULL
 * \param[in] length Topic data size. Cannot be zero.
 */
typedef void (*vs_cloud_mb_process_custom_topic_cb_t)(const char *topic,
                                                      uint16_t topic_sz,
                                                      const uint8_t *data,
                                                      uint16_t length);

/** Implementation for default topics processing
 *
 * Virgil IoT KIT preprocesses topics from #vs_cloud_mb_topic_id_t enumeration. It calls this function when receives
 * a notification about a new version of Trust List or Firmware
 * to load data for this topic.
 *
 * \param[in] url URL where user can fetch a new version of file.
 * \param[in] length Topic URL size.
 */
typedef void (*vs_cloud_mb_process_default_topic_cb_t)(const uint8_t *url, uint16_t length);

/** Register processing handlers for default topics from #vs_cloud_mb_topic_id_t enumeration
 *
 * Registers topic processing handlers.
 *
 * \param[in] topic_id Topic identifier.
 * \param[in] handler Topic processing implementation. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_message_bin_register_default_handler(vs_cloud_mb_topic_id_t topic_id,
                                              vs_cloud_mb_process_default_topic_cb_t handler);

/** Register custom handler implementation
 *
 * Registers custom topics processing.
 * You can use #vs_cloud_message_bin_register_default_handler() if it is enough for your default topics processing.
 *
 * \param[in] handler Custom topics processing handler. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_message_bin_register_custom_handler(vs_cloud_mb_process_custom_topic_cb_t handler);

/** Message bin initialization
 *
 * This implementation initializes MQTT with specified URL and certificates.
 * #vs_aws_message_bin_impl() returns #vs_cloud_message_bin_impl_t structure with default implementation provided by
 * Virgil IoT KIT library. You can analyze function which \a init member points to for an example.
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

/** Message bin connection and subscription to topic implementation
 *
 * This implementation connects to the message bin broker and subscribes to topics.
 * #vs_aws_message_bin_impl() returns #vs_cloud_message_bin_impl_t structure with default implementation provided by
 * Virgil IoT KIT library. You can analyze function which \a connect_subscribe member points to for an example.
 *
 * \param[in] client_id Client identifier. Cannot be NULL.
 * \param[in] login Login. Cannot be NULL.
 * \param[in] password Password. Cannot be NULL.
 * \param[in] topic_list Pointer to the list of topics. Cannot be NULL.
 * \param[in] process_topic Implementation for topics processing. Cannot be NULL.
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
 * Implementation for message bin processing.
 * #vs_aws_message_bin_impl() returns #vs_cloud_message_bin_impl_t structure with default implementation provided by
 * Virgil IoT KIT library. You can analyze function which \a process member points to for an example.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_cloud_mb_process_func_t)(void);

/** Message Bin implementation */
typedef struct {
    vs_cloud_mb_init_func_t init;                           /**< Message bin initialization */
    vs_cloud_mb_connect_subscribe_func_t connect_subscribe; /**< Message bin connection and topic subscribing */
    vs_cloud_mb_process_func_t
            process; /**< Message bin processing : listen incoming messages and executing implementation calls */
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
 * \param[in] message_bin_impl Message bin implementation. You can use default implementation
 * returned by #vs_aws_message_bin_impl(). Must not be NULL.
 * \param[in] secmodule Security module implementation. You can use default implementation
 * returned by #vs_soft_secmodule_impl(). Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_cloud_init(const vs_cloud_impl_t *cloud_impl,
              const vs_cloud_message_bin_impl_t *message_bin_impl,
              vs_secmodule_impl_t *secmodule);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_CLOUD_H
