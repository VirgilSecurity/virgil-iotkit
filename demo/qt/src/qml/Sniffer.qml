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


import QtQuick 2.5
import QtQuick.Controls 2.12
import QtQuick.Window 2.2
import QtQuick.Layouts 1.1

Item {
    ColumnLayout {

        anchors.fill: parent
        anchors.leftMargin: 5
        anchors.rightMargin: 5

        spacing: 2

        Title {
            text: qsTr("Sniffer")
        }

        ListView {
            id: sniffer

            Layout.fillHeight: true
            Layout.fillWidth: true

            model: SnapSniffer

            delegate: Item
            {
                id: listDelegate
                width: parent.width
                height: bottomMargin.y + bottomMargin.height

                Rectangle {
                    anchors.fill: parent
                    color: "#303030"
                }

                Item {
                    id: topMargin
                    anchors.top: parent.top
                    height: applicationWindow.margin * 2
                }

                Text {
                    id: line1
                    anchors.top: topMargin.top
                    wrapMode: Text.Wrap
                    width: parent.width
                    color: "yellow"
                    text: timestamp + " : " + macSrc + " ==> " + macDst
                }

                Text {
                    id: line2
                    anchors.top: line1.bottom
                    wrapMode: Text.Wrap
                    width: parent.width
                    color: "lightBlue"
                    text: serviceId + " : " + elementId
                }

                Text {
                    id: line3
                    anchors.top: line2.bottom
                    wrapMode: Text.Wrap
                    width: parent.width
                    color: "white"
                    text: contentSize + " bytes : " + content
                }

                Item {
                    id: bottomMargin
                    anchors.top: line3.bottom
                    height: applicationWindow.margin * 2
                }

            }
        }
    }
}
