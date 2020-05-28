#!/bin/bash

#
#   Global variables
#
SCRIPT_FOLDER="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR_BASE=${SCRIPT_FOLDER}/..
export QT_INSTALL_DIR_BASE=${SCRIPT_FOLDER}/../../../prebuilt

#
#   Includes
#
source ${SCRIPT_FOLDER}/ish/error.ish

#
#   Arguments
#
PLATFORM=$1
PLATFORM_DIR=""
ANDROID_NDK=$2
ANDROID_ABI=$3
[[ ! -z "$4" ]] && ANDROID_PLATFORM=" -DANDROID_PLATFORM=$4"

#
# Check platform
#
if [ $(uname) == "Darwin" ]; then
    HOST_PLATFORM="darwin-x86_64"
elif [ $(uname) == "Linux" ]; then
    HOST_PLATFORM="linux-x86_64"
else
    echo "Wrong platform $(uname). Supported only: [Linux, Darwin]"
    exit 1
fi

if [ ${PLATFORM} == "android" ]; then
    export BUILD_DIR_SUFFIX=${PLATFORM}.${ANDROID_ABI}
    export AR_TOOLS_ANDROID=${ANDROID_NDK}/toolchains/aarch64-linux-android-4.9/prebuilt/${HOST_PLATFORM}/bin/aarch64-linux-android-ar
else
    export BUILD_DIR_SUFFIX=${PLATFORM}
fi

echo ">>> PLATFORM = ${PLATFORM}"
echo ">>> BUILD_DIR_SUFFIX = ${BUILD_DIR_SUFFIX}"
echo ">>> ANDROID_NDK = ${ANDROID_NDK}"
echo ">>> ANDROID_ABI = ${ANDROID_ABI}"
echo ">>> ANDROID_PLATFORM = ${ANDROID_PLATFORM}"

###########################################################################################################################
#
#   Build dependencies for vs-module-messenger
#
function build_messenger_deps() {
    echo "===================================="
    echo "=== Building depends"
    echo "===================================="

    echo
    echo "=== Build Virgil Crypto C libs"
    echo
    if [ "${CFG_BUILD_VS_CRYPTO}" == "off" ]; then
        echo
        echo "Skip due to config parameter CFG_BUILD_VS_CRYPTO"
        echo
    else
        ${SCRIPT_FOLDER}/build-virgil-crypto-c.sh ${@}
        check_error
    fi
    echo
    echo "=== Build Virgil SDK C++ C libs"
    echo
    if [ "${CFG_BUILD_VS_SDK_CPP}" == "off" ]; then
        echo
        echo "Skip due to config parameter CFG_BUILD_VS_SDK_CPP"
        echo
    else
        ${SCRIPT_FOLDER}/build-virgil-sdk-cpp.sh ${@}
        check_error
    fi
}
###########################################################################################################################
#
#   Build
#
function build() {
    BUILD_TYPE=$1
    CMAKE_ARGUMENTS=$2
    CMAKE_DEPS_ARGUMENTS=$3
    CORES=10
    
    build_messenger_deps ${CMAKE_DEPS_ARGUMENTS}
    BUILD_DIR=${BUILD_DIR_BASE}/cmake-build-${BUILD_DIR_SUFFIX}/${BUILD_TYPE}

    echo
    echo "===================================="
    echo "=== ${PLATFORM} ${BUILD_TYPE} build"
    echo "=== Output directory: ${BUILD_DIR}"
    echo "===================================="
    echo

    rm -rf ${BUILD_DIR}
    mkdir -p ${BUILD_DIR}

    pushd ${BUILD_DIR}

    cmake ${BUILD_DIR_BASE} ${CMAKE_ARGUMENTS} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
        -DVIRGIL_PLATFORM_LIBS_DIR=${QT_INSTALL_DIR_BASE} \
        -DVIRGIL_PLATFORM=${BUILD_DIR_SUFFIX} \
        -DVIRGIL_IOT_MESSENGER_INTERNAL_XMPP=OFF \
        -DGO_DISABLE=ON \
        -G "Unix Makefiles"
    check_error

    make DESTDIR=${QT_INSTALL_DIR_BASE}/${BUILD_DIR_SUFFIX}/${BUILD_TYPE}/installed install
    check_error

    popd
}
###########################################################################################################################
#
#   Prepare cmake parameters
#
function prep_param() {
   local BUILD_TYPE="${1}"
   #
   #   MacOS
   #
   if [[ "${PLATFORM}" == "macos" ]]; then
       CMAKE_DEPS_ARGUMENTS=" \
       "
       CMAKE_ARGUMENTS=" \
           -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
           -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl@1.1/1.1.1d \
       "
   
   #
   #   Windows (mingw) over Linux
   #
   elif [[ "${PLATFORM}" == "windows" && "$(uname)" == "Linux" ]]; then
       CMAKE_DEPS_ARGUMENTS=" \
           -DCMAKE_TOOLCHAIN_FILE=/usr/share/mingw/toolchain-mingw64.cmake \
           -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 \
           -DCYGWIN=1 \
       "
       CMAKE_ARGUMENTS=" \
           -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
           -DCMAKE_TOOLCHAIN_FILE=/usr/share/mingw/toolchain-mingw64.cmake \
           -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 \
           -DOS=WINDOWS \
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
   #   Linux
   #
   elif [[ "${PLATFORM}" == "linux" ]]; then
       CMAKE_DEPS_ARGUMENTS=" \
       "
       CMAKE_ARGUMENTS=" \
           -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
       "
   
   #
   #   iOS
   #
   elif [[ "${PLATFORM}" == "ios" ]]; then
       CMAKE_DEPS_ARGUMENTS=" \
           -DCMAKE_TOOLCHAIN_FILE=${BUILD_DIR_BASE}/cmake/toolchain/apple.cmake \
           -DCURL_ROOT_DIR=${QT_INSTALL_DIR_BASE}/${BUILD_DIR_SUFFIX}/${BUILD_TYPE}/installed/usr/local/ \
        "
       CMAKE_ARGUMENTS=" \
           -DAPPLE_PLATFORM="IOS" \
           -DAPPLE_BITCODE=OFF \
           -DCMAKE_TOOLCHAIN_FILE="${BUILD_DIR_BASE}/cmake/toolchain/apple.cmake" \
           -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
           -DCMAKE_INSTALL_NAME_TOOL=/usr/bin/install_name_tool \
           -DCURL_ROOT_DIR=${QT_INSTALL_DIR_BASE}/${BUILD_DIR_SUFFIX}/${BUILD_TYPE}/installed/usr/local/ \
       "
   
   #
   #   iOS Simulator
   #
   elif [[ "${PLATFORM}" == "ios-sim" ]]; then
       CMAKE_DEPS_ARGUMENTS=" \
           -DAPPLE_PLATFORM="IOS_SIM64" \
           -DAPPLE_BITCODE=OFF \
           -DCMAKE_TOOLCHAIN_FILE=${BUILD_DIR_BASE}/cmake/toolchain/apple.cmake \
           -DCURL_ROOT_DIR=${QT_INSTALL_DIR_BASE}/${BUILD_DIR_SUFFIX}/${BUILD_TYPE}/installed/usr/local/ \
       "
       CMAKE_ARGUMENTS=" \
           -DAPPLE_PLATFORM="IOS_SIM64" \
           -DAPPLE_BITCODE=OFF \
           -DCMAKE_TOOLCHAIN_FILE="${BUILD_DIR_BASE}/cmake/toolchain/apple.cmake" \
           -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
           -DCMAKE_INSTALL_NAME_TOOL=/usr/bin/install_name_tool \
       "
   
   #
   #   Android
   #
   elif [[ "${PLATFORM}" == "android" ]]; then
       CMAKE_DEPS_ARGUMENTS=" \
           -DCMAKE_CROSSCOMPILING=ON \
           -DANDROID=ON \
           -DANDROID_QT=ON  \
           ${ANDROID_PLATFORM} \
           -DANDROID_ABI=${ANDROID_ABI} \
           -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake \
           -DCURL_ROOT_DIR=${QT_INSTALL_DIR_BASE}/${BUILD_DIR_SUFFIX}/${BUILD_TYPE}/installed/usr/local/ \
       "
       #    TODO : use fat libraries
       CMAKE_ARGUMENTS=" \
           -DANDROID_QT=ON \
           ${ANDROID_PLATFORM} \
           -DANDROID_ABI=${ANDROID_ABI} \
           -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake \
           -DVIRGIL_IOT_CONFIG_DIRECTORY=${BUILD_DIR_BASE}/config/pc \
       "
   
   else
       echo " Virgil IoTKIT build script usage : "
       echo " $0 platform platform-specific"
       echo " where : "
       echo "    platform - platform selector. Currently supported: android, ios, ios-sim, linux, macos, mingw32, windows"
       echo "    platform-specific for Android :"
       echo "      android_ABI [android_platform]"
       exit 1
   fi
}

#########################################################################################################   
#
#   Build both Debug and Release
#
prep_param "debug"
build "debug" "${CMAKE_ARGUMENTS}" "${CMAKE_DEPS_ARGUMENTS}"

prep_param "release"
build "release" "${CMAKE_ARGUMENTS}" "${CMAKE_DEPS_ARGUMENTS}"
         