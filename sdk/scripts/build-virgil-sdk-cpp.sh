#!/bin/bash

#
#   Global variables
#
SCRIPT_FOLDER="$( cd "$( dirname "$0" )" && pwd )"
CPP_SDK_DIR="${SCRIPT_FOLDER}/../ext/virgil-sdk-cpp"
BUILD_DIR_BASE="${CPP_SDK_DIR}"

#
#   Arguments
#
PLATFORM="host"

#
#   Pack libraries to one
#
function pack_libs() {
    LIBS_DIR=${1}
    SUFFIX=${2}
    FINAL_LIB="libvscppsdk${SUFFIX}.a"

    pushd ${LIBS_DIR}

      local LIBS=( "libed25519.a" "libmbedcrypto.a" "libmbedtls.a" "libmbedx509.a" "librestless.a" "libvirgil_crypto${SUFFIX}.a" "libvirgil_sdk${SUFFIX}.a")

      # Split static lib to object files
		  for LIB in "${LIBS[@]}"; do
		      ar x ${LIB}
		      rm ${LIB}
		  done

			# Combine all object files to a static lib
			ar rcs ${FINAL_LIB} *.o

      # Clean up object files
      rm *.o

    popd
}

#
#   Build
#
function build() {
    local BUILD_TYPE=$1
    local CMAKE_ARGUMENTS=$2
    local CORES=10

    local BUILD_DIR=${BUILD_DIR_BASE}/cmake-build-${PLATFORM}/${BUILD_TYPE}
    local INSTALL_DIR=${BUILD_DIR_BASE}/cmake-build-${PLATFORM}/${BUILD_TYPE}/installed
    local LIBS_DIR=${INSTALL_DIR}/usr/local/lib

    echo
    echo "===================================="
    echo "=== ${PLATFORM} ${BUILD_TYPE} build"
    echo "=== Output directory: ${BUILD_DIR}"
    echo "===================================="
    echo

    rm -rf ${BUILD_DIR}
    mkdir -p ${BUILD_DIR}
    mkdir -p ${INSTALL_DIR}
    pushd ${BUILD_DIR}
      # prepare to build
      cmake ${BUILD_DIR_BASE} ${CMAKE_ARGUMENTS} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -G "Unix Makefiles"

      # build all targets
      make -j ${CORES}

      # install all targets
      make DESTDIR=${INSTALL_DIR} install

      # pack libraries into one
      if [ "$BUILD_TYPE" = "debug" ]; then
          local SUFFIX="_d"
      else
          local SUFFIX=""
      fi
      pack_libs ${LIBS_DIR} ${SUFFIX}

    popd
}

# Common CMake arguments for the project
CMAKE_ARGUMENTS="-DCMAKE_CXX_FLAGS='-fvisibility=hidden' -DCMAKE_C_FLAGS='-fvisibility=hidden' -DENABLE_TESTING=OFF -DINSTALL_EXT_LIBS=ON -DINSTALL_EXT_HEADERS=ON"

#
#   Build both Debug and Release
#
build "debug" "${CMAKE_ARGUMENTS}"
build "release" "${CMAKE_ARGUMENTS}"
