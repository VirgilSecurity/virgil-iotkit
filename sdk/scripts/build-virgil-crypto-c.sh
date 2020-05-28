#!/bin/bash

#
#   Global variables
#
SCRIPT_FOLDER="$(cd "$(dirname "$0")" && pwd)"

CRYPTO_C_DIR="${SCRIPT_FOLDER}/../ext/virgil-crypto-c"
BUILD_DIR_BASE="${CRYPTO_C_DIR}"
CMAKE_CUSTOM_PARAM="${@}"

if [[ $@ == *"toolchain-mingw64.cmake"* ]]; then
    echo "############"
    echo "### mingw64 toolchain file detected"
    echo "############"
    AR_TOOLS="x86_64-w64-mingw32-ar"
    OBJ_EXT="obj"
elif [[ $@ == *"android.toolchain.cmake"* ]]; then
    echo "############"
    echo "### android toolchain file detected"
    echo "############"
    AR_TOOLS="${AR_TOOLS_ANDROID}"
    OBJ_EXT="o"
    echo "AR_TOOLS = $AR_TOOLS"
elif [[ $@ == *"apple.cmake"* ]]; then
    echo "############"
    echo "### apple toolchain file detected"
    echo "############"
    if [[ $@ != *"IOS_SIM"* ]]; then
        IOS_ARCH="armv7 armv7s arm64"
    fi
    AR_TOOLS="ar"
    OBJ_EXT="o"
    IS_IOS="true"
else
    AR_TOOLS="ar"
    OBJ_EXT="o"
    [ "$(arch)" == "x86_64" ] && LIB_ARCH="64" || LIB_ARCH=""
fi

#
#   Includes
#
source ${SCRIPT_FOLDER}/ish/error.ish
source ${SCRIPT_FOLDER}/ish/lib-utils.ish

#
#   Build
#
function build() {
    local BUILD_TYPE=$1
    local CMAKE_ARGUMENTS=$2
    local CORES=10

    local BUILD_DIR=${BUILD_DIR_BASE}/cmake-build-${BUILD_DIR_SUFFIX}/${BUILD_TYPE}
    local INSTALL_DIR=${QT_INSTALL_DIR_BASE}/${BUILD_DIR_SUFFIX}/${BUILD_TYPE}/installed
    local LIBS_DIR=${INSTALL_DIR}/usr/local/lib${LIB_ARCH}

    echo
    echo "===================================="
    echo "=== ${BUILD_DIR_SUFFIX} ${BUILD_TYPE} build"
    echo "=== Output directory: ${BUILD_DIR}"
    echo "===================================="
    echo

    rm -rf ${BUILD_DIR}
    mkdir -p ${BUILD_DIR}
    mkdir -p ${INSTALL_DIR}

    pushd ${BUILD_DIR}
    # prepare to build
    echo "==========="
    echo "=== Run CMAKE "
    echo "==========="
    cmake ${BUILD_DIR_BASE} ${CMAKE_ARGUMENTS} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -G "Unix Makefiles"
    check_error

    # build all targets
    echo "==========="
    echo "=== Building"
    echo "==========="
    make -j ${CORES}
    check_error

    # install all targets
    echo "==========="
    echo "=== Installing"
    echo "==========="
    make DESTDIR=${INSTALL_DIR} install
    check_error

    if [ "${IS_IOS}" == "true" ]; then
        get_lib_ios "${LIBS_DIR}" "VSCCommon" "libvsc_common.a"
        get_lib_ios "${LIBS_DIR}" "VSCFoundation" "libvsc_foundation.a"
    fi

      if [ "${BUILD_TYPE}" == "debug" ]; then 
        pushd ${LIBS_DIR}      
        echo "=== Rename debug library"
        mv -f libed25519_d.a           libed25519.a
        mv -f libprotobuf-nanopbd.a    libprotobuf-nanopb.a
        mv -f libvsc_common_d.a        libvsc_common.a
        mv -f libvsc_foundation_d.a    libvsc_foundation.a
        mv -f libvsc_foundation_pb_d.a libvsc_foundation_pb.a
        popd
      fi 

    echo "=== Packing libraries"
    pack_libs ${LIBS_DIR} "libed25519.a libmbedcrypto.a libprotobuf-nanopb.a libvsc_common.a libvsc_foundation.a libvsc_foundation_pb.a" "libvscryptoc.a"

    # Clean
    rm -rf ${INSTALL_DIR}/$(echo "$HOME" | cut -d "/" -f2)

    popd
}

# Common CMake arguments for the project
CMAKE_ARGUMENTS="-DCMAKE_CXX_FLAGS='-fvisibility=hidden' -DCMAKE_C_FLAGS='-fvisibility=hidden' \
-DENABLE_CLANGFORMAT=OFF \
-DENABLE_CLANGFORMAT=OFF \
-DVIRGIL_PHP_TESTING=OFF \
-DVIRGIL_LIB_PYTHIA=OFF \
-DVIRGIL_LIB_RATCHET=OFF \
-DVIRGIL_LIB_PHE=OFF \
-DVIRGIL_POST_QUANTUM=OFF \
${CMAKE_CUSTOM_PARAM}"

#
#   Build both Debug and Release
#
build "debug" "${CMAKE_ARGUMENTS}"
build "release" "${CMAKE_ARGUMENTS}"
