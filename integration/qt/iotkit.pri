CONFIG += c++14

#
#   Project relative path
#

VIRGIL_IOTKIT_SOURCE_PATH = $$PWD/../../
VIRGIL_IOTKIT_BUILD_PATH_BASE = $${VIRGIL_IOTKIT_SOURCE_PATH}

CONFIG(debug, debug|release) {
    BUILD_TYPE = debug
}
CONFIG(release, debug|release) {
    BUILD_TYPE = release
}

unix:mac:      OS_NAME = macos
unix:ios:      OS_NAME = ios
linux:android: OS_NAME = android
linux:         OS_NAME = linux

VIRGIL_IOTKIT_BUILD_PATH = $${VIRGIL_IOTKIT_BUILD_PATH_BASE}/cmake-build-$${OS_NAME}/$${BUILD_TYPE}

message("Virgil IoTKIT libraries : $${VIRGIL_IOTKIT_BUILD_PATH}")

#
#   Headers
#
INC_HELPERS = $$PWD/facade/include/virgil/iot/qt/helpers
HEADERS += \
        $$PWD/default-impl/netif/udp-broadcast/include/virgil/iot/qt/netif/VSQUdpBroadcast.h \
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
        $$PWD/facade/include/virgil/iot/qt/VSQIoTKit.h \
        $$PWD/facade/include/virgil/iot/qt/protocols/snap/VSQNetifBase.h \
        $$PWD/facade/include/virgil/iot/qt/protocols/snap/VSQSnapServiceBase.h \
        $$PWD/facade/include/virgil/iot/qt/protocols/snap/VSQSnapINFOClient.h

#
#   Sources
#
SRC_HELPERS = $$PWD/facade/src/helpers
SOURCES += \
        $$PWD/default-impl/netif/udp-broadcast/src/VSQUdpBroadcast.cpp \
        $${SRC_HELPERS}/VSQDeviceRoles.cpp \
        $${SRC_HELPERS}/VSQDeviceSerial.cpp \
        $${SRC_HELPERS}/VSQDeviceType.cpp \
        $${SRC_HELPERS}/VSQFileVersion.cpp \
        $${SRC_HELPERS}/VSQIoTKitFacade.cpp \
        $${SRC_HELPERS}/VSQMac.cpp \
        $${SRC_HELPERS}/VSQManufactureId.cpp \
        $$PWD/facade/src/VSQNetifBase.cpp \
        $$PWD/facade/src/VSQSnapINFOClient.cpp

#
#   Libraries
#
defineReplace(add_virgiliotkit_library) {
    LIBRARY_PATH = $$1
    LIBRARY_NAME = $$2
    !exists($${VIRGIL_IOTKIT_BUILD_PATH}/$${LIBRARY_PATH}/*$${LIBRARY_NAME}.*): error("Library $${LIBRARY_NAME} has not been found in $${VIRGIL_IOTKIT_BUILD_PATH}/$${LIBRARY_PATH}. Need to rebuild Virgil IoTKit")
    return (-L$${VIRGIL_IOTKIT_BUILD_PATH}/$${LIBRARY_PATH} -l$${LIBRARY_NAME})
}

LIBS += $$add_virgiliotkit_library("modules/logger",         "vs-module-logger")
LIBS += $$add_virgiliotkit_library("modules/provision",      "vs-module-provision")
LIBS += $$add_virgiliotkit_library("modules/protocols/snap", "vs-module-snap-control")

#
#   Include path
#
INCLUDEPATH +=  $$PWD/default-impl/netif/udp-broadcast/include \
                $$PWD/facade/include \
                \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/modules/logger/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/modules/provision/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/modules/provision/trust_list/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/modules/protocols/snap/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/modules/crypto/secmodule/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/helpers/status_code/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/helpers/macros/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/helpers/storage_hal/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/helpers/update/include \
                $${VIRGIL_IOTKIT_SOURCE_PATH}/config/pc

#
#   Compiler options
#
linux:!android: QMAKE_CFLAGS+=-Wno-multichar
linux:!android: QMAKE_CXXFLAGS+=-Wno-multichar