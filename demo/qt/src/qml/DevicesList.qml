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
import QtQuick.Window 2.2
import QtQuick.Layouts 1.1

Item {
    property var listItemHeight

    ColumnLayout {

        anchors.fill: parent
        anchors.leftMargin: 5
        anchors.rightMargin: 5

        spacing: 2

        Title {
            text: qsTr("Devices list")
        }

        ListView {
            property int margin
            property string evenGradientColor: "#20FFFFFF"
            Layout.fillHeight: true
            Layout.fillWidth: true


            model: SnapInfoClient

            ScrollBar.vertical: ScrollBar {}

            delegate: Item
            {
                id: listDelegate
                width: parent.width
                height: devicesList.listItemHeight
                property var dataLeft: height + 3 * margin
                property string evenGradientColor: "#20FFFFFF"

                Layout.fillHeight: true
                Layout.fillWidth: true

                Rectangle {
                    id: rowBackground
                    anchors.fill: parent
                    gradient: Gradient {
                        orientation: Gradient.Horizontal
                        GradientStop{ position: 0; color: index % 2 ? evenGradientColor : "#00000000" }
                        GradientStop{ position: 0.5; color: index % 2 ? evenGradientColor : "#00000000" }
                        GradientStop{ position: 1; color: "#00000000" }
                    }

                }

                GridLayout {
                    id: row
                    anchors.fill: parent
                    rows: 3
                    flow: GridLayout.TopToBottom
                    property var squareSide: parent.height - 2 * margin

                    Item {
                        Layout.rowSpan: 3
                        width: 0.1
                    }

                    Rectangle {
                        Layout.rowSpan: 3
                        Layout.fillHeight: true

                        id: roleItemBackground
                        color: "#004000"
                        Layout.minimumWidth: row.squareSide
                        Layout.preferredWidth: row.squareSide
                        Layout.maximumWidth: row.squareSide
                        Layout.minimumHeight: row.squareSide
                        Layout.preferredHeight: row.squareSide
                        Layout.maximumHeight: row.squareSide
                        Layout.alignment: Qt.AlignLeft | Qt.AlignVCenter

                        Text {
                            id: roleItemText
                            anchors.fill: parent
                            font.pointSize: dataFontSize
                            color: "white"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                            text: deviceRoles
                        }
                    }

                    Text {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        horizontalAlignment: Text.AlignLeft
                        verticalAlignment: Text.AlignBottom
                        color: "yellow"
                        text: isActive ? "active" : "not active"
                    }

                    Text {
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignLeft
                        verticalAlignment: Text.AlignVCenter
                        color: "white"
                        text: macAddress
                    }

                    Text {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        horizontalAlignment: Text.AlignLeft
                        verticalAlignment: Text.AlignTop
                        color: "white"
                        text: "fw " + fwVer + ", tl " + tlVer
                    }
                }
            }
        }
    }
}
