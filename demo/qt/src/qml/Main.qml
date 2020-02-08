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
import QtQuick.Layouts 1.5

ApplicationWindow {

    id: applicationWindow
    visible: true
    title: qsTr("Virgil IoTKit Qt Demo")
    background: Rectangle {
        color: "#303030"
    }

    property int dpi: Screen.pixelDensity * 25.4
    property int desktopDPI: 120
    property int dip2pixels: 160

    function dp(x) {
        if(dpi < desktopDPI) {
            return x
        } else {
            return x * (dpi / dip2pixels)
        }
    }

    property int footerHeight: dp(80)
    property int listItemHeight: dp(80)
    property int minWidthPerElement : 200
    property int elementCount : 3
    property int margin: dp(5)
    property int dataFontSize: 15
    property bool allChildren: true
    property int currentMenuId: Main.MenuId.DevicesListId

    function recalculateChildren() {
        allChildren = width > (elementCount * minWidthPerElement)
    }

    enum MenuId {
        SnifferId,
        DevicesListId,
        BLEId
    }

    function menuItemSelected(menuId) {
        currentMenuId = menuId
        recalculateChildren()
    }

    RowLayout {
        anchors.fill: parent

        DevicesList {
            id: devicesList

            Layout.fillHeight: true
            Layout.fillWidth: true

            listItemHeight: applicationWindow.listItemHeight
            visible: allChildren || currentMenuId === Main.MenuId.DevicesListId
        }

        Sniffer {
            id: sniffer

            Layout.fillHeight: true
            Layout.fillWidth: true

            visible: allChildren || currentMenuId === Main.MenuId.SnifferId
        }

        BLEManager {
            id: btScanerForm

            Layout.fillHeight: true
            Layout.fillWidth: true

            visible: allChildren || currentMenuId === Main.MenuId.BLEId
        }
    }

    footer: Rectangle {
        height: footerHeight
        color: "black"
        visible: !allChildren

        RowLayout {
            anchors.fill: parent

            Item { Layout.fillWidth: true }

            Button {
                id: devicesListButton
                text: qsTr("Devices")
                onClicked: applicationWindow.menuItemSelected(Main.MenuId.DevicesListId)
                palette {
                    button: { devicesList.visible ? "steelblue" : "aliceblue" }
                }
            }

            Item { Layout.fillWidth: true }

            Button {
                id: snifferButton
                text: qsTr("Sniffer")
                onClicked: applicationWindow.menuItemSelected(Main.MenuId.SnifferId)
                palette {
                    button: { sniffer.visible ? "steelblue" : "aliceblue" }
                }
            }

            Item { Layout.fillWidth: true }

            Button {
                id: bleButton
                text: qsTr("BLE")
                onClicked: applicationWindow.menuItemSelected(Main.MenuId.BLEId)
                palette {
                    button: { btScanerForm.visible ? "steelblue" : "aliceblue" }
                }
            }

            Item { Layout.fillWidth: true }
        }
    }

    onWidthChanged: {
        recalculateChildren()
    }

    onHeightChanged: {
        recalculateChildren()
    }

}
