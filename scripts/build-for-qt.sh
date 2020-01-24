#!/bin/bash

#
#   Global variables
#
SCRIPT_FOLDER="$( cd "$( dirname "$0" )" && pwd )"
BUILD_DIR_BASE=${SCRIPT_FOLDER}/..

#
#   Arguments
#
PLATFORM=$1

#
#   Build
#
function build() {
    BUILD_TYPE=$1
    CMAKE_ARGUMENTS=$2
    CORES=10

    BUILD_DIR=${BUILD_DIR_BASE}/cmake-build-${PLATFORM}/${BUILD_TYPE}

    echo
    echo "===================================="
    echo "=== ${PLATFORM} ${BUILD_TYPE} build"
    echo "=== Output directory: ${BUILD_DIR}"
    echo "===================================="
    echo

    rm -rf ${BUILD_DIR}
    mkdir -p ${BUILD_DIR}
    pushd ${BUILD_DIR}
    cmake ${BUILD_DIR_BASE} ${CMAKE_ARGUMENTS} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DGO_DISABLE=ON -G "Unix Makefiles"

    make -j ${CORES} vs-module-logger
    make -j ${CORES} vs-module-provision
    make -j ${CORES} vs-module-snap-control

    popd
}

#
#   Prepare cmake parameters
#

#
#   MacOS, Linux
#
if [[ "${PLATFORM}" == "macos" || "${PLATFORM}" == "linux" ]]; then

    CMAKE_ARGUMENTS=" \
        -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
    "

#
#   Host OS: mingw32
#
elif [[ "${PLATFORM}" == "mingw32" ]]; then

    CMAKE_ARGUMENTS=" \
        -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
        -DOS=WINDOWS \
        -DCMAKE_TOOLCHAIN_FILE="${BUILD_DIR_BASE}/cmake/mingw32.toolchain.cmake"
    "

#
#   Windows
#
elif [[ "${PLATFORM}" == "windows" ]]; then

    CMAKE_ARGUMENTS=" \
        -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
        -DOS=WINDOWS \
    "

#
#   iOS
#
elif [[ "${PLATFORM}" == "ios" ]]; then

    CMAKE_ARGUMENTS=" \
        -DAPPLE_PLATFORM="IOS" \
        -DCMAKE_TOOLCHAIN_FILE="${BUILD_DIR_BASE}/cmake/toolchain/apple.cmake" \
        -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
    "

#
#   iOS Simulator
#
elif [[ "${PLATFORM}" == "ios-sim" ]]; then

    CMAKE_ARGUMENTS=" \
        -DAPPLE_PLATFORM="IOS_SIM" \
        -DCMAKE_TOOLCHAIN_FILE="${BUILD_DIR_BASE}/cmake/toolchain/apple.cmake" \
        -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
    "

#
#   Android
#
elif [[ "${PLATFORM}" == "android" ]]; then

    ANDROID_ABI=$2

    [[ ! -z "$3" ]] && ANDROID_PLATFORM=" -DANDROID_PLATFORM=$3"

#    TODO : use fat libraries

    CMAKE_ARGUMENTS=" \
        -DANDROID_QT=ON \
        ${ANDROID_PLATFORM} \
        -DANDROID_ABI=${ANDROID_ABI} \
        -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake \
        -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
    "
    PLATFORM="${PLATFORM}.${ANDROID_ABI}"

else
    echo "Virgil IoTKIT build script usage : "
    echo "$0 platform platform-specific"
    echo "where : "
    echo "   platform - platform selector. Currently supported: android, ios, ios-sim, linux, macos, mingw32, windows"
    echo "   platform-specific for Android :"
    echo "     android_ABI [android_platform]"

    exit 1
fi


#
#   Build both Debug and Release
#
build "debug" "${CMAKE_ARGUMENTS}"
build "release" "${CMAKE_ARGUMENTS}"
