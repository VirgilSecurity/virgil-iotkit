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

import QtQuick 2.12
import QtQuick.Controls 2.12
import QtQuick.Layouts 1.12

Dialog {

    property string ssid: editSSID.text
    property string pass: editPass.text
    property string account: editAccount.text

    x: (parent.width - width) / 2
    y: (parent.height - height) / 2
    visible: true
    title: qsTr("Initialization parameters")
    standardButtons: Dialog.Apply | Dialog.Cancel

    contentItem: Rectangle {
        color: "darkgrey"
        implicitWidth: 400
        implicitHeight: 200

        Label {
            id: labelWiFi
            text: "WiFi SSID"
            color: "black"
        }

        TextField {
            id: editSSID
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: labelWiFi.bottom
            anchors.topMargin: 3

            color: "black"
            placeholderText: qsTr("WiFi SSID")
            echoMode: TextInput.Normal
        }

        Label {
            id: labelPass
            text: "WiFi Password"
            anchors.top: editSSID.bottom
            anchors.topMargin: 10
            color: "black"
        }

        TextField {
            id: editPass
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: labelPass.bottom
            anchors.topMargin: 3

            color: "black"
            placeholderText: qsTr("WiFi Password")
        }

        Label {
            id: labelAccount
            text: "Account"
            anchors.top: editPass.bottom
            anchors.topMargin: 10
            color: "black"
        }

        TextField {
            id: editAccount
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: labelAccount.bottom
            anchors.topMargin: 3

            color: "black"
            placeholderText: qsTr("Account")
        }
    }
}
