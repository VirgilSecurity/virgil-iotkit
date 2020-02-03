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

/*! \file snap-structs.h
 * \brief SNAP structures
 *
 */

#ifndef VS_SNAP_STRUCTS_H
#define VS_SNAP_STRUCTS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <virgil/iot/provision/provision-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

struct vs_netif_t;
struct vs_mac_addr_t;

#define VS_SNAP_NETIF_MAX (5) /**< Maximum amout of network interfaces */

/**  SNAP transaction ID
 */
typedef uint16_t vs_snap_transaction_id_t;

/**  SNAP service ID
 *
 * Used to identify service. Library provides FLDT, INFO, PRVS services.
 */
typedef uint32_t vs_snap_service_id_t;

/**  SNAP element ID.
 *
 * Used by service to identify its request/process commands.
 */
typedef uint32_t vs_snap_element_t;

/** Received data
 *
 * Callback for #vs_netif_init_t function callback.
 * This callback is used when new SNAP data has been loaded.
 *
 * \param[in] netif #vs_netif_t Network interface. Cannot be NULL.
 * \param[in] data Received portion of data. Cannot be NULL.
 * \param[in] data_sz Size in bytes of data portion. Cannot be zero.
 * \param[out] packet_data Buffer to store packed data. Cannot be NULL.
 * \param[out] packet_data_sz Output buffer to store packet data size in bytes. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_netif_rx_cb_t)(struct vs_netif_t *netif,
                                        const uint8_t *data,
                                        const uint16_t data_sz,
                                        const uint8_t **packet_data,
                                        uint16_t *packet_data_sz);

/** Preprocessed data
 *
 * Callback for #vs_netif_init_t function callback.
 * This callback is used to preprocess data.
 *
 * \param[in] netif #vs_netif_t Network interface. Cannot be NULL.
 * \param[in] data Data buffer. Cannot be NULL.
 * \param[in] data_sz Size in bytes of data portion. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_netif_process_cb_t)(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);

/** Send data
 *
 * Callback for \a tx member of #vs_netif_t structure.
 * This callback is used to send data.
 * Called from #vs_snap_send call.
 *
 * \param[in] netif #vs_netif_t Network interface. Cannot be NULL.
 * \param[in] data Data buffer. Cannot be NULL.
 * \param[in] data_sz Size in bytes of data portion. Cannot be zero.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_netif_tx_t)(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz);

/** Get MAC address
 *
 * Callback for \a mac_addr member of #vs_netif_t structure.
 * This callback is used to receive current MAC address.
 * Called from #vs_snap_mac_addr call.
 *
 * \param[in] netif #vs_netif_t Network interface. Cannot be NULL.
 * \param[out] mac_addr #vs_mac_addr_t MAC address buffer. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_netif_mac_t)(const struct vs_netif_t *netif, struct vs_mac_addr_t *mac_addr);

/** Initializer
 *
 * Callback for \a init member of #vs_netif_t structure.
 * This callback is used to initialize SNAP implementation.
 * Called from #vs_snap_init call.
 *
 * \param[in] netif #vs_netif_t Network interface. Cannot be NULL.
 * \param[in] rx_cb #vs_netif_rx_cb_t callback. Cannot be NULL.
 * \param[in] process_cb #vs_netif_process_cb_t callback. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_netif_init_t)(struct vs_netif_t *netif,
                                       const vs_netif_rx_cb_t rx_cb,
                                       const vs_netif_process_cb_t process_cb);

/** Destructor
 *
 * Callback for \a deinit member of #vs_netif_t structure.
 * This callback is used to destroy SNAP implementation.
 * Called from #vs_snap_deinit call.
 *
 * \param[in] netif #vs_netif_t Network interface. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_netif_deinit_t)(struct vs_netif_t *netif);

/** SNAP Service Request Processor
 *
 * Callback for \a request_process member of #vs_snap_service_t structure.
 * This callback is called to process SNAP service \a request and to prepare \a response if needed.
 *
 * \param[in] netif Network interface.
 * \param[in] element_id #vs_snap_element_t service element. Normally this is command ID.
 * \param[in] request Request data buffer.
 * \param[in] request_sz Request data size.
 * \param[out] response Response output buffer.
 * \param[in] response_buf_sz Response output buffer size.
 * \param[out] response_sz Stored output data size. Must be not more than \a response_buf_size. Cannot be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_service_request_processor_t)(const struct vs_netif_t *netif,
                                                           vs_snap_element_t element_id,
                                                           const uint8_t *request,
                                                           const uint16_t request_sz,
                                                           uint8_t *response,
                                                           const uint16_t response_buf_sz,
                                                           uint16_t *response_sz);

/** SNAP Service Response Processor
 *
 * Callback for \a response_process member of #vs_snap_service_t structure.
 * This callback is called to process SNAP service response.
 *
 * \param[in] netif Network interface.
 * \param[in] element_id #vs_snap_element_t service element. Normally this is command ID.
 * \param[in] is_ack Boolean flag indicating successful packet receiving
 * \param[in] response Response buffer.
 * \param[in] response_sz Response size.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_service_response_processor_t)(const struct vs_netif_t *netif,
                                                            vs_snap_element_t element_id,
                                                            bool is_ack,
                                                            const uint8_t *response,
                                                            const uint16_t response_sz);

/** SNAP Periodical data
 *
 * Callback for \a periodical_process member of #vs_snap_service_t structure.
 * This callback is called when there is no input data.
 * It can be used to send some statistical data as it is done for INFO service.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_service_periodical_processor_t)(void);

/** SNAP Service Destructor
 *
 * Callback for \a deinit member of #vs_snap_service_t structure.
 * This callback is called to destroy SNAP service.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
typedef vs_status_e (*vs_snap_service_deinit_t)(void);

/** Device roles
 *
 * Enumeration with mask bits to describe device roles.
 */
typedef enum {
    VS_SNAP_DEV_GATEWAY = HTONL_IN_COMPILE_TIME(0x0001),    /**< Gateway role */
    VS_SNAP_DEV_THING = HTONL_IN_COMPILE_TIME(0x0002),      /**< Thing role */
    VS_SNAP_DEV_CONTROL = HTONL_IN_COMPILE_TIME(0x0004),    /**< Control role */
    VS_SNAP_DEV_LOGGER = HTONL_IN_COMPILE_TIME(0x0008),     /**< Logger role */
    VS_SNAP_DEV_SNIFFER = HTONL_IN_COMPILE_TIME(0x0010),    /**< Sniffer role */
    VS_SNAP_DEV_DEBUGGER = HTONL_IN_COMPILE_TIME(0x0020),   /**< Debugger role */
    VS_SNAP_DEV_INITIALIZER = HTONL_IN_COMPILE_TIME(0x0040) /**< Initializer role */
} vs_snap_device_role_e;

#define ETH_ADDR_LEN (6)
#define ETH_TYPE_LEN (2)
#define ETH_CRC_LEN (4)
#define ETH_HEADER_LEN (ETH_ADDR_LEN + ETH_ADDR_LEN + ETH_TYPE_LEN)
#define ETH_MIN_LEN (64)
#define ETH_MTU (1500)

#define VS_ETHERTYPE_VIRGIL (HTONS_IN_COMPILE_TIME(0xABCD))

/** SNAP Flags */
typedef enum {
    VS_SNAP_FLAG_ACK = HTONL_IN_COMPILE_TIME(0x0001), /**< Confirmation about receiving a correct packet */
    VS_SNAP_FLAG_NACK = HTONL_IN_COMPILE_TIME(0x0002) /**< Notification about rejecting a packet */
} vs_snap_flags_e;

/******************************************************************************/
/** MAC address
 */
typedef struct __attribute__((__packed__)) vs_mac_addr_t {
    uint8_t bytes[ETH_ADDR_LEN]; /**< MAC address bytes */
} vs_mac_addr_t;

/******************************************************************************/
/** Ethernet header
 */
typedef struct __attribute__((__packed__)) ethernet_header {
    vs_mac_addr_t dest; /**< Destination MAC address */
    vs_mac_addr_t src;  /**< Source MAC address */
    uint16_t type;      /**< Ethernet packet type */
} vs_ethernet_header_t;

/******************************************************************************/
/** SNAP packet header
 */
typedef struct __attribute__((__packed__)) {
    vs_snap_transaction_id_t transaction_id;                /**< Transaction ID */
    vs_snap_service_id_t service_id; /**< SNAP service */   // CODEGEN: SKIP
    vs_snap_element_t element_id; /**< Service's command */ // CODEGEN: SKIP
    uint32_t flags; /**< Packet flags */                    // CODEGEN: SKIP
    uint16_t padding;                                       /**< Packet padding */
    uint16_t content_size;                                  /**< Packet #vs_snap_packet_t \a content data size */
} vs_snap_header_t;

/******************************************************************************/
/** SNAP packet
 */
typedef struct __attribute__((__packed__)) {
    vs_ethernet_header_t eth_header; /**< Ethernet header */
    vs_snap_header_t header;         /**< Packet header */
    uint8_t content[];               /**< Packet data with \a header . \a content_size bytes size */
} vs_snap_packet_t;

#define VS_NETIF_PACKET_BUF_SIZE (1024)

/******************************************************************************/
/** Network interface
 *
 * This structure contains network interface callbacks and packet data
 */
typedef struct vs_netif_t {
    void *user_data; /**< User data */

    // Functions
    vs_netif_init_t init;     /**< Initialization */
    vs_netif_deinit_t deinit; /**< Destroy */
    vs_netif_tx_t tx;         /**< Transmit data */
    vs_netif_mac_t mac_addr;  /**< MAC address */

    // Incoming packet
    uint8_t packet_buf[VS_NETIF_PACKET_BUF_SIZE]; /**< Packet buffer */
    uint16_t packet_buf_filled;                   /**< Packet size */
} vs_netif_t;

/******************************************************************************/
/** SNAP service descriptor
 *
 * This structure contains SNAP service callbacks and service specific information
 */
typedef struct {
    void *user_data;                                           /**< User data */
    vs_snap_service_id_t id;                                   /**< Service ID */
    vs_snap_service_request_processor_t request_process;       /**< Reqeust processing */
    vs_snap_service_response_processor_t response_process;     /**< Response processing */
    vs_snap_service_periodical_processor_t periodical_process; /**< Periodical task */
    vs_snap_service_deinit_t deinit;                           /**< Destructor call */
} vs_snap_service_t;

/******************************************************************************/
/** SNAP statistics
 */
typedef struct {
    uint32_t sent;     /**< Sends amount */
    uint32_t received; /**< Receives amount */
} vs_snap_stat_t;

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_SNAP_STRUCTS_H
