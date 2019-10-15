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

project(vs-default-soft-hsm VERSION 0.1.0 LANGUAGES C)

add_library(vs-default-soft-hsm)

target_sources(vs-default-soft-hsm
        PRIVATE

        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/vs-softhsm/vs-softhsm.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/vs-softhsm/helpers/asn1-cryptogram.h
        ${CMAKE_CURRENT_LIST_DIR}/include/private/vs-softhsm-internal.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/vs-softhsm.c
        ${CMAKE_CURRENT_LIST_DIR}/src/softhsm-slots.c
        ${CMAKE_CURRENT_LIST_DIR}/src/softhsm-ecies.c
        ${CMAKE_CURRENT_LIST_DIR}/src/softhsm-sha2.c
        ${CMAKE_CURRENT_LIST_DIR}/src/softhsm-crypto.c
        ${CMAKE_CURRENT_LIST_DIR}/src/softhsm-keypair.c
        ${CMAKE_CURRENT_LIST_DIR}/src/helpers/asn1-cryptogram.c
        )

#
#	Path to crypto lib
#
if (BIGENDIAN_64_BIT_BUILD)
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../ext/deps/mips64")
elseif(BIGENDIAN_32_BIT_BUILD)
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../ext/deps/mips32")
else()
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../ext/deps/host")
endif ()

include(GNUInstallDirs)
if(EXISTS "${CRYPTO_C_BASE_DIR}")
    set(CRYPTO_C_INCLUDES "${CRYPTO_C_BASE_DIR}/include")
    set(CRYPTO_C_LIBS "${CRYPTO_C_BASE_DIR}/lib")
else()
    set(CRYPTO_C_INCLUDES "/usr/include/cryptoc-shsm")
    set(CRYPTO_C_LIBS "/usr/${CMAKE_INSTALL_LIBDIR}/cryptoc-shsm")
endif ()

#
#   Common include directories
#
target_include_directories(vs-default-soft-hsm
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        ${CRYPTO_C_INCLUDES}
        ${CRYPTO_C_INCLUDES}/virgil/crypto/common

        INTERFACE
        $<INSTALL_INTERFACE:include>
        )

#
#   Link libraries
#
target_link_libraries(vs-default-soft-hsm
        PUBLIC
        converters
        hsm
        storage_hal
        ${CRYPTO_C_LIBS}/libvsc_foundation.a
        ${CRYPTO_C_LIBS}/libvsc_common.a
        ${CRYPTO_C_LIBS}/libmbedcrypto.a
        ${CRYPTO_C_LIBS}/libed25519.a
        )

if(COMMAND add_clangformat)
    add_clangformat(vs-default-soft-hsm)
endif()


