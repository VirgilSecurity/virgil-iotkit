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

#include <virgil/iot/qt/VSQIoTKit.h>
#include <virgil/iot/qt/protocols/snap/VSQNetifBase.h>

using namespace VirgilIoTKit;

VSQNetifBase::VSQNetifBase() {
    // User data points to this object
    m_lowLevelNetif.user_data = this;

    // Prepare functionality implementations
    m_lowLevelNetif.init = initCb;
    m_lowLevelNetif.deinit = deinitCb;
    m_lowLevelNetif.tx = txCb;
    m_lowLevelNetif.mac_addr = macAddrCb;

    // Prepare buffer to receive data
    m_lowLevelNetif.packet_buf_filled = 0;
}

bool
VSQNetifBase::processData(const QByteArray &data) {
    if (!m_lowLevelRxCall)
        return false;

    if (!data.size())
        return false;

    const uint8_t *raw_data = reinterpret_cast<const uint8_t *>(data.data());
    const uint8_t *packet_data = nullptr;
    uint16_t packet_data_sz = 0;

    if (m_lowLevelRxCall(&m_lowLevelNetif, raw_data, data.size(), &packet_data, &packet_data_sz) !=
        VirgilIoTKit::VS_CODE_OK)
        return false;

    if (!m_lowLevelPacketProcess)
        return true;

    if (receivers(SIGNAL(fireNewPacket(VSQSnapPacket))) > 0) {
        VSQSnapPacket snapPacket;
        const VirgilIoTKit::vs_snap_packet_t *srcPacket =
                reinterpret_cast<const VirgilIoTKit::vs_snap_packet_t *>(packet_data);

        snapPacket.m_timestamp = QDateTime::currentDateTime();
        snapPacket.m_dest = srcPacket->eth_header.dest;
        snapPacket.m_src = srcPacket->eth_header.src;
        snapPacket.m_ethernetPacketType = srcPacket->eth_header.type;
        snapPacket.m_transactionId = srcPacket->header.transaction_id;
        snapPacket.m_serviceId = srcPacket->header.service_id;
        snapPacket.m_elementId = srcPacket->header.element_id;
        snapPacket.m_flags = srcPacket->header.flags;
        snapPacket.m_content = QByteArray::fromRawData(reinterpret_cast<const char *>(srcPacket->content),
                                                       srcPacket->header.content_size);

        emit fireNewPacket(snapPacket);
    }

    if (m_lowLevelPacketProcess(&m_lowLevelNetif, packet_data, packet_data_sz) != VirgilIoTKit::VS_CODE_OK) {
        VS_LOG_ERROR("Unable to process received packet");
        return false;
    }

    return true;
}

VirgilIoTKit::vs_status_e
VSQNetifBase::initCb(struct VirgilIoTKit::vs_netif_t *netif,
                     const VirgilIoTKit::vs_netif_rx_cb_t rx_cb,
                     const VirgilIoTKit::vs_netif_process_cb_t process_cb) {
    VSQNetifBase *instance = reinterpret_cast<VSQNetifBase *>(netif->user_data);

    instance->m_lowLevelRxCall = rx_cb;
    instance->m_lowLevelPacketProcess = process_cb;

    return instance->init() ? VirgilIoTKit::VS_CODE_OK : VirgilIoTKit::VS_CODE_ERR_INIT_SNAP;
}

VirgilIoTKit::vs_status_e
VSQNetifBase::deinitCb(struct VirgilIoTKit::vs_netif_t *netif) {
    VSQNetifBase *instance = reinterpret_cast<VSQNetifBase *>(netif->user_data);

    return instance->deinit() ? VirgilIoTKit::VS_CODE_OK : VirgilIoTKit::VS_CODE_ERR_DEINIT_SNAP;
}

VirgilIoTKit::vs_status_e
VSQNetifBase::txCb(struct VirgilIoTKit::vs_netif_t *netif, const uint8_t *data_raw, const uint16_t data_sz) {
    VSQNetifBase *instance = reinterpret_cast<VSQNetifBase *>(netif->user_data);

    return instance->tx(QByteArray(reinterpret_cast<const char *>(data_raw), data_sz))
                   ? VirgilIoTKit::VS_CODE_OK
                   : VirgilIoTKit::VS_CODE_ERR_TX_SNAP;
}

VirgilIoTKit::vs_status_e
VSQNetifBase::macAddrCb(const struct VirgilIoTKit::vs_netif_t *netif, struct VirgilIoTKit::vs_mac_addr_t *mac_addr) {
    VSQNetifBase *instance = reinterpret_cast<VSQNetifBase *>(netif->user_data);
    QString macStr = instance->macAddr();
    VSQMac macInternal = macStr;

    *mac_addr = macInternal;

    return VirgilIoTKit::VS_CODE_OK;
}

void VSQNetifBase::resetPacketForced() {
    m_lowLevelNetif.packet_buf_filled = 0;
}
