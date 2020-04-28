#  Copyright (C) 2015-2020 Virgil Security, Inc.
#
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#      (1) Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#
#      (2) Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#
#      (3) Neither the name of the copyright holder nor the names of its
#      contributors may be used to endorse or promote products derived from
#      this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#
#  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

CONFIG += c++14

CONFIG(debug, debug|release) {
    BUILD_TYPE = debug
}
CONFIG(release, debug|release) {
    BUILD_TYPE = release
}

win32 {
    QMAKE_CFLAGS += -mno-ms-bitfields
    QMAKE_CXXFLAGS += -mno-ms-bitfields
}

DLL_EXT = "dylib"

unix:mac:                   OS_NAME = macos
linux:android:              OS_NAME = android.$$ANDROID_TARGET_ARCH
linux:!android:             OS_NAME = linux
win32:                      OS_NAME = windows

CONFIG(iphonesimulator, iphoneos | iphonesimulator) {
    OS_NAME = ios-sim
}

CONFIG(iphoneos, iphoneos | iphonesimulator) {
    OS_NAME = ios
}

PREBUILT_SYSROOT = $$PREBUILT_PATH/$${OS_NAME}/release/installed/usr/local
message("PREBUILT_SYSROOT : $${PREBUILT_SYSROOT}")

#
#   Headers
#

INC_SNAP = $$PWD/facade/include/virgil/iot/qt/protocols/snap
INC_HELPERS = $$PWD/facade/include/virgil/iot/qt/helpers
HEADERS += \
        $$PWD/default-impl/netif/udp-broadcast/include/virgil/iot/qt/netif/VSQUdpBroadcast.h \
#        $$PWD/default-impl/netif/websocket/include/virgil/iot/qt/netif/VSQNetifWebsocket.h \
        $$PWD/default-impl/netif/ble/include/virgil/iot/qt/netif/VSQNetifBLE.h \
        $$PWD/default-impl/netif/ble/include/virgil/iot/qt/netif/VSQNetifBLEEnumerator.h \
        $${INC_HELPERS}/VSQAppConfig.h \
        $${INC_HELPERS}/VSQDeviceRoles.h \
        $${INC_HELPERS}/VSQDeviceSerial.h \
        $${INC_HELPERS}/VSQDeviceType.h \
        $${INC_HELPERS}/VSQFeatures.h \
        $${INC_HELPERS}/VSQFileVersion.h \
        $${INC_HELPERS}/VSQImplementations.h \
        $${INC_HELPERS}/VSQIoTKitFacade.h \
        $${INC_HELPERS}/VSQMac.h \
        $${INC_HELPERS}/VSQManufactureId.h \
        $${INC_HELPERS}/VSQSingleton.h \
        $${INC_HELPERS}/VSQHelpers.h \
        $$PWD/facade/include/virgil/iot/qt/VSQIoTKit.h \
        $${INC_SNAP}/VSQNetifBase.h \
        $${INC_SNAP}/VSQSnapServiceBase.h \
        $$PWD/facade/include/virgil/iot/qt/protocols/snap/VSQSnapCFGClient.h \
        $${INC_SNAP}/VSQSnapINFOClient.h \
        $${INC_SNAP}/VSQSnapINFOClientQml.h \
        $${INC_SNAP}/VSQSnapSnifferQml.h

#
#   Sources
#

SRC_SNAP = $$PWD/facade/src
SRC_HELPERS = $$PWD/facade/src/helpers
SOURCES += \
        $$PWD/default-impl/netif/udp-broadcast/src/VSQUdpBroadcast.cpp \
#        $$PWD/default-impl/netif/websocket/src/VSQNetifWebsocket.cpp \
        $$PWD/default-impl/netif/ble/src/VSQNetifBLE.cpp \
        $$PWD/default-impl/netif/ble/src/VSQNetifBLEEnumerator.cpp \
        $$PWD/default-impl/hal.cpp \
        $${SRC_HELPERS}/VSQDeviceRoles.cpp \
        $${SRC_HELPERS}/VSQDeviceSerial.cpp \
        $${SRC_HELPERS}/VSQDeviceType.cpp \
        $${SRC_HELPERS}/VSQFileVersion.cpp \
        $${SRC_HELPERS}/VSQIoTKitFacade.cpp \
        $${SRC_HELPERS}/VSQMac.cpp \
        $${SRC_HELPERS}/VSQManufactureId.cpp \
        $${SRC_SNAP}/VSQNetifBase.cpp \
        $${SRC_SNAP}/VSQSnapINFOClient.cpp \
        $$PWD/facade/src/VSQSnapCFGClient.cpp \
        $${SRC_SNAP}/VSQSnapINFOClientQml.cpp \
        $${SRC_SNAP}/VSQSnapSnifferQml.cpp

#
#   Copy shared lobraries
#
unix:mac: {
    DST_DLL = $${OUT_PWD}/$${TARGET}.app/Contents/Frameworks
    MESSENGER_INTERNAL_DLL = $${PREBUILT_SYSROOT}/lib/libvs-messenger-internal.$${DLL_EXT}
    MESSENGER_CRYPTO_DLL = $${PREBUILT_SYSROOT}/lib/libvs-messenger-crypto.$${DLL_EXT}
    QMAKE_POST_LINK += $$quote(mkdir -p $${DST_DLL}/$$escape_expand(\n\t))
    QMAKE_POST_LINK += $$quote(cp $${MESSENGER_INTERNAL_DLL} $${DST_DLL}/$$escape_expand(\n\t))
    QMAKE_POST_LINK += $$quote(cp $${MESSENGER_CRYPTO_DLL} $${DST_DLL}/$$escape_expand(\n\t))
}

#
#   Libraries
#

LIBS += -L$${PREBUILT_SYSROOT}/lib
LIBS += -lvs-module-logger
LIBS += -lvs-module-provision
LIBS += -lvs-module-snap-control
LIBS += -lvs-module-secbox
LIBS += -lvs-module-messenger

win32: {
	LIBS += -lws2_32
        LIBS += $${PREBUILT_SYSROOT}/lib/libvs-messenger-crypto.dll.a
        LIBS += $${PREBUILT_SYSROOT}/lib/libvs-messenger-internal.dll.a
} else: {
        LIBS += -lvs-messenger-crypto
        LIBS += -lvs-messenger-internal
}

#
#   Include path
#
INCLUDEPATH +=  $$PWD/default-impl/netif/udp-broadcast/include \
                $$PWD/default-impl/netif/websocket/include \
                $$PWD/default-impl/netif/ble/include \
                $$PWD/facade/include \
                \
                $${PREBUILT_SYSROOT}/include \
                $$PWD/config/pc

#
#   Compiler options
#

win32|linux:!android: QMAKE_CFLAGS+=-Wno-multichar
win32|linux:!android: QMAKE_CXXFLAGS+=-Wno-multichar
