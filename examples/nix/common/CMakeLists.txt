#   Copyright (C) 2015-2019 Virgil Security Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(virgil-iot-examples-common VERSION 0.1.0 LANGUAGES C)

add_library(virgil-iot-examples-common)

#
#  Path to crypto lib
#
if (BIGENDIAN_64_BIT_BUILD)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/mips64.toolchain.cmake")
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/deps/mips64")
endif ()

if (BIGENDIAN_32_BIT_BUILD)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/mips32.toolchain.cmake")
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/../deps/mips32")
endif ()

if (NOT BIGENDIAN_64_BIT_BUILD AND NOT BIGENDIAN_32_BIT_BUILD)
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/../deps/host")
endif()

include(GNUInstallDirs)
if(EXISTS "${CRYPTO_C_BASE_DIR}")
    set(CRYPTO_C_INCLUDES "${CRYPTO_C_BASE_DIR}/include")
    set(CRYPTO_C_LIBS "${CRYPTO_C_BASE_DIR}/lib")
else()
    set(CRYPTO_C_INCLUDES "/usr/include/cryptoc-shsm")
    set(CRYPTO_C_LIBS "/usr/${CMAKE_INSTALL_LIBDIR}/cryptoc-shsm")
endif ()

#
#  Source files
#
target_sources(virgil-iot-examples-common
        PRIVATE
        include/virgil/iot/examples/secbox-impl.h

        src/nix-crypto-impl.c
        src/nix-file-cache-impl.c
        src/nix-file-io-impl.c
        src/nix-keypair-impl.c
        src/nix-global-impl.c
        src/nix-storage-impl.c
        )

#
#  Linked libraries
#
target_link_libraries(virgil-iot-examples-common
        PRIVATE
        secbox
        virgil-iot-status-code
        converters
        ${CRYPTO_C_LIBS}/libvsc_foundation.a
        ${CRYPTO_C_LIBS}/libvsc_common.a
        ${CRYPTO_C_LIBS}/libmbedcrypto.a
        ${CRYPTO_C_LIBS}/libed25519.a
        )

#
#  Included directories
#
target_include_directories(virgil-iot-examples-common
        PRIVATE
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
        ${CRYPTO_C_INCLUDES}
        ${CRYPTO_C_INCLUDES}/virgil/crypto/common
        include/virgil/iot/examples

        PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
        )

