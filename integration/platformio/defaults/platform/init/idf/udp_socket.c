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

#include <platform/init/idf/udp_socket.h>

static int udb_broadcast_sock;
static uint16_t udb_broadcast_port = 0;
uint8_t *rx_buffer = NULL;
uint16_t rx_buffer_size = 0;
static UBaseType_t initialized = 0;

// ********************* Receive pkgs callback ********************************
void __attribute__((weak)) udp_server_recv_cb(struct sockaddr_in from_source, uint8_t *rx_buffer, uint16_t recv_size) {
    VS_LOG_DEBUG("Default empty udp_server_recv_cb has been called");
}

//******************************************************************************
static void
udp_server_task(void *pvParameters) {
    struct sockaddr_in source_addr;
    socklen_t source_socklen = sizeof(source_addr);
    struct sockaddr_in bindaddr;
    int ret_res = 0;
    int recv_len;
    if (!rx_buffer) {
        VS_LOG_ERROR("Alocate RX buff size", errno);
        rx_buffer = pvPortMalloc(rx_buffer_size);
    }

    initialized = 1;

    while (1) {
        bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        bindaddr.sin_family = AF_INET;
        bindaddr.sin_port = htons(udb_broadcast_port);

        // Create socket
        udb_broadcast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udb_broadcast_sock < 0) {
            VS_LOG_ERROR("Unable to create socket: errno %d", errno);
            ret_res = ESP_FAIL;
            break;
        }
        // Bind socket
        ret_res = bind(udb_broadcast_sock, (struct sockaddr *)&bindaddr, sizeof(bindaddr));
        if (ret_res < 0) {
            VS_LOG_ERROR("Socket unable to bind: errno %d", errno);
            break;
        }

        // Wait and receive data loop
        while (1) {
            VS_LOG_DEBUG("Socket wait data");
            recv_len = recvfrom(
                    udb_broadcast_sock, rx_buffer, rx_buffer_size, 0, (struct sockaddr *)&source_addr, &source_socklen);
            // Error occured during receiving
            VS_LOG_DEBUG("Socket recvfrom. recv_len:  %d", recv_len);
            if (recv_len < 0) {
                VS_LOG_ERROR("Socket recvfrom failed: errno %d", errno);
                break;
            }
            // Data received
            else {
                VS_LOG_HEX(VS_LOGLEV_DEBUG, "udp_server_task. RECV DUMP:", rx_buffer, recv_len);
                udp_server_recv_cb(source_addr, rx_buffer, recv_len);
            }
        }

        if (udb_broadcast_sock != -1) {
            VS_LOG_DEBUG("Shutting down socket and restarting...");
            shutdown(udb_broadcast_sock, 0);
            close(udb_broadcast_sock);
        }
    }
    initialized = 0;
    vPortFree(rx_buffer);
    vTaskDelete(NULL);
}

//******************************************************************************
int
udp_socket_send_broadcast(const void *tx_buffer, size_t size, int flags) {
    struct sockaddr_in dstaddr_broadcast;
    dstaddr_broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    dstaddr_broadcast.sin_family = AF_INET;
    dstaddr_broadcast.sin_port = htons(udb_broadcast_port);

    CHECK_RET(initialized, ESP_FAIL, "upd socket isn't initialized");

    VS_LOG_DEBUG("Sending broadcast: size %d", size);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "udp_socket_send_broadcast. SEND DUMP:", tx_buffer, size);

    int err = sendto(udb_broadcast_sock,
                     tx_buffer,
                     size,
                     flags,
                     (struct sockaddr *)&dstaddr_broadcast,
                     sizeof(dstaddr_broadcast));

    VS_LOG_DEBUG("POST: Sending broadcast: size %d, ERR/SENDED: [%d]", size, err);
    // vTaskDelay(1000 / portTICK_PERIOD_MS);

    if (err < 0) {
        VS_LOG_DEBUG("Error occured during socket sending: errno %d", errno);
        return err;
    }
    return ESP_OK;
}

//******************************************************************************
int
udp_socket_send_to(const void *tx_buffer, size_t size, int flags, in_addr_t dest) {
    struct sockaddr_in dst_addr;
    int err = 0;

    CHECK_RET(initialized, ESP_FAIL, "upd socket isn't initialized");

    dst_addr.sin_addr.s_addr = dest;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(udb_broadcast_port);

    err = sendto(udb_broadcast_sock, tx_buffer, size, flags, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    VS_LOG_DEBUG("Sended count: [%d]", err);
    if (err < 0) {
        VS_LOG_DEBUG("Error occured during socket sending: [%d]", err);
        return err;
    }
    return ESP_OK;
}

//******************************************************************************
BaseType_t
udp_socket_init(uint16_t udb_port, uint16_t rxbuf_size) {
    udb_broadcast_port = udb_port;
    rx_buffer_size = rxbuf_size;
    return xTaskCreate(udp_server_task, "udp_server", 4 * 4096, NULL, 3, NULL);
}