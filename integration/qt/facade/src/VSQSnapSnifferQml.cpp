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

VSQSnapSnifferQml::VSQSnapSnifferQml(const VSQSnapSnifferQmlConfig &snifferConfig, VSQNetifBase *netif)
    : m_maxPacketsAmount(snifferConfig.maxLogLines()) {
    Q_CHECK_PTR(netif);

    QObject::connect(netif, &VSQNetifBase::fireNewPacket, this, &VSQSnapSnifferQml::onNewPacket);
}

void
VSQSnapSnifferQml::onNewPacket(VSQSnapPacket packet) {

    if (m_packets.size() == m_maxPacketsAmount) {
        beginRemoveRows(QModelIndex(), m_packets.size() - 1, m_packets.size() - 1);
        m_packets.removeLast();
        endRemoveRows();
    }

    beginInsertRows(QModelIndex(), 0, 0);
    m_packets.insert(m_packets.begin(), packet);
    endInsertRows();
}

int
VSQSnapSnifferQml::rowCount(const QModelIndex &parent) const {
    Q_UNUSED(parent);
    return m_packets.size();
}

QVariant
VSQSnapSnifferQml::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= m_packets.size())
        return QVariant();

    auto packetIt = m_packets.cbegin();

    for (int pos = 0; pos < index.row(); ++pos, ++packetIt)
        ;

    const VSQSnapPacket &packet = *packetIt;

    switch (role) {
    case MacDst:
        return packet.m_dest.description();
    case MacSrc:
        return packet.m_src.description();
    case EthernetPacketType:
        return QString("%1h").arg(packet.m_ethernetPacketType, 4, 16, QChar('0'));
    case TransactionId:
        return QString("%1").arg(packet.m_transactionId);
    case Flags:
        return QString("%1h").arg(packet.m_flags, 0, 16);
    case Timestamp:
        return packet.m_timestamp.toString("H:mm:ss");
    case ContentSize:
        return packet.m_content.size();
    case ServiceId:
    case ElementId: {
        uint32_t rawData = role == ServiceId ? packet.m_serviceId : packet.m_elementId;
        char symbols[4];
        for (auto byte = 0; byte < 4; ++byte) {
            symbols[byte] = rawData & 0xFF;
            rawData >>= 8;
        }

        return QString::fromLocal8Bit(symbols, 4);
    }

    case Content: {
        QString res;
        bool firstByte = true;

        for (uint8_t byte : packet.m_content) {
            if (!firstByte) {
                res += ".";
            }

            res += QString("%1").arg(byte, 2, 16, QChar('0'));
            firstByte = false;
        }

        return res;
    }

    default:
        Q_ASSERT(false);
        return QString("Unsupported");
    }
}

QHash<int, QByteArray>
VSQSnapSnifferQml::roleNames() const {
    static const QHash<int, QByteArray> roles{{MacDst, "macDst"},
                                              {MacSrc, "macSrc"},
                                              {EthernetPacketType, "ethernetPacketType"},
                                              {TransactionId, "transactionId"},
                                              {ServiceId, "serviceId"},
                                              {ElementId, "elementId"},
                                              {Flags, "flags"},
                                              {Content, "content"},
                                              {ContentSize, "contentSize"},
                                              {Timestamp, "timestamp"}};

    return roles;
}
