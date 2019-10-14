#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="/tmp/build"
INSTALL_DIR_HOST="${SCRIPT_FOLDER}/../ext/deps/host"
INSTALL_DIR_MIPS_64="${SCRIPT_FOLDER}/../ext/deps/mips64"
INSTALL_DIR_MIPS_32="${SCRIPT_FOLDER}/../ext/deps/mips32"

TOOLCHAIN_MIPS_64="${SCRIPT_FOLDER}/../cmake/mips64.toolchain.cmake"
TOOLCHAIN_MIPS_32="${SCRIPT_FOLDER}/../cmake/mips32.toolchain.cmake"

function create_clean_dir() {
  if [ -d "${1}" ]; then
    rm -rf "${1}"
  fi
  mkdir -p "${1}"
}

function build() {
    local _install_prefix="${1}"

    create_clean_dir "${BUILD_DIR}"
    create_clean_dir "${_install_prefix}"

    if [[ -z "${2}" ]]; then
        local _toolchain=""
    else
        local _toolchain="-DCMAKE_TOOLCHAIN_FILE=${2}"
    fi

    pushd "${BUILD_DIR}"
        git clone https://github.com/VirgilSecurity/virgil-crypto-c
        cd virgil-crypto-c
        git checkout 1d52c33953f1d692f1f28757f14947f3a003577e
        cmake -DCMAKE_INSTALL_PREFIX="${_install_prefix}" "${_toolchain}" -DENABLE_TESTING=OFF -DVIRGIL_C_TESTING=OFF -DVIRGIL_LIB_PYTHIA=OFF -DVIRGIL_LIB_RATCHET=OFF -DVIRGIL_LIB_PHE=OFF -Bbuild -H.
        cmake --build build
        cmake --build build --target install
        popd

        if [ -d "${_install_prefix}/lib64" ]; then
            mv -f "${_install_prefix}/lib64" "${_install_prefix}/lib"
        fi
}


echo "------ Build on HOST machine --------"
build "${INSTALL_DIR_HOST}"

if [ "${1}" == "all" ]; then
  echo "--------- Build for MIPS 64 ---------"
  build "${INSTALL_DIR_MIPS_64}" "${TOOLCHAIN_MIPS_64}"

  echo "--------- Build for MIPS 32 ---------"
  build "${INSTALL_DIR_MIPS_32}" "${TOOLCHAIN_MIPS_32}"
fi
