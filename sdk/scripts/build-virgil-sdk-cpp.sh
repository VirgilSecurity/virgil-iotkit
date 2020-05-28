#!/bin/bash

#
#   Global variables
#
SCRIPT_FOLDER="$(cd "$(dirname "$0")" && pwd)"

CPP_SDK_DIR="${SCRIPT_FOLDER}/../ext/virgil-sdk-cpp"
BUILD_DIR_BASE="${CPP_SDK_DIR}"
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
  local LIBS_DIR=${INSTALL_DIR}/usr/local/lib

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
  echo "##################################"
  echo "### cmake ${BUILD_DIR_BASE} ${CMAKE_ARGUMENTS} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -G Unix Makefiles"
  echo "##################################"
  cmake ${BUILD_DIR_BASE} ${CMAKE_ARGUMENTS} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -G "Unix Makefiles"
  check_error

  # build all targets
  make -j ${CORES}
  check_error

  # install all targets
  make DESTDIR=${INSTALL_DIR} install
  check_error

  # pack libraries into one
  if [ "$BUILD_TYPE" = "debug" ]; then
    local SUFFIX="_d"
  else
    local SUFFIX=""
  fi

  if [ "${IS_IOS}" == "true" ]; then
    get_lib_ios "${LIBS_DIR}" "VSCCrypto" "libvirgil_crypto${SUFFIX}.a"
  fi

  echo "=== Packing libraries"
  pack_libs ${LIBS_DIR} "libed25519.a libmbedcrypto.a libmbedtls.a libmbedx509.a librestless.a libvirgil_crypto${SUFFIX}.a libvirgil_sdk${SUFFIX}.a" "libvscppsdk.a"

  popd
}

# Common CMake arguments for the project
CMAKE_ARGUMENTS="-DCMAKE_CXX_FLAGS='-fvisibility=hidden' \
                 -DCMAKE_C_FLAGS='-fvisibility=hidden' \
                 -DCMAKE_ARGS='-DCMAKE_POSITION_INDEPENDENT_CODE=ON' \
                 -DENABLE_TESTING=OFF \
                 -DINSTALL_EXT_LIBS=ON \
                 -DINSTALL_EXT_HEADERS=ON \
                 ${CMAKE_CUSTOM_PARAM}"

#
#   Build both Debug and Release
#
build "debug" "${CMAKE_ARGUMENTS}"
build "release" "${CMAKE_ARGUMENTS}"
