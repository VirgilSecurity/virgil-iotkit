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

#include <msgr/msgr-client-impl.h>
#include <virgil/iot/protocols/snap.h>

#include "threads/msgr-thread.h"

static vs_status_e
_snap_msgr_start_notif_cb(vs_snap_msgr_device_t *device);

static vs_status_e
_snap_msgr_device_data_cb(uint8_t *data, uint32_t data_sz);

/******************************************************************************/
static vs_status_e
_snap_msgr_start_notif_cb(vs_snap_msgr_device_t *device) {
    VS_LOG_DEBUG("MSGR thing device start. mac = %x:%x:%x:%x:%x:%x",
                 device->mac[0],
                 device->mac[1],
                 device->mac[2],
                 device->mac[3],
                 device->mac[4],
                 device->mac[5]);
    vs_snap_msgr_set_polling(vs_snap_netif_routing(), (vs_mac_addr_t *)device->mac, true, MSGR_POLL_PERIOD_S);
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_snap_msgr_device_data_cb(uint8_t *data, uint32_t data_sz) {
    CHECK_RET(
            vs_msgr_send_message_to_messenger(data, data_sz), VS_CODE_ERR_REQUEST_PREPARE, "Can't process the message");
    return VS_CODE_OK;
}

/******************************************************************************/
vs_snap_msgr_client_service_t
vs_snap_msgr_client_impl(void) {
    vs_snap_msgr_client_service_t msgr_client_cb = {_snap_msgr_start_notif_cb, _snap_msgr_device_data_cb};
    return msgr_client_cb;
}
