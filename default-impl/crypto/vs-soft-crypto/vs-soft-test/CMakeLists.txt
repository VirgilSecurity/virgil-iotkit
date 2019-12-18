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

project(vs-default-soft-crypto-tests VERSION 0.1.0 LANGUAGES C)

#
#  Test library for soft implemenation
#

add_library(vs-default-soft-crypto-test)

target_sources(vs-default-soft-crypto-test
        PRIVATE
        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/private/test-hl-keys-data.h
        ${CMAKE_CURRENT_LIST_DIR}/include/private/test-tl-data.h
        ${CMAKE_CURRENT_LIST_DIR}/include/private/soft-test-helpers.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/vs-soft-test/vs-soft-test.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/aes.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/ecdh.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/ecdsa.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/hash.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/hmac.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/kdf.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/keypair.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/virgil-ecies.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/random.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/trust-list.c
        ${CMAKE_CURRENT_LIST_DIR}/src/secbox/secbox-test.c

        ${CMAKE_CURRENT_LIST_DIR}/src/firmware/firmware_test.c

        ${CMAKE_CURRENT_LIST_DIR}/src/test_data/test-hl-keys-data.c
        ${CMAKE_CURRENT_LIST_DIR}/src/test_data/test-tl-data.c

        ${CMAKE_CURRENT_LIST_DIR}/src/helpers/crypto-helpers.c
        ${CMAKE_CURRENT_LIST_DIR}/src/vs-soft-crypto-test.c

        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/helpers/firmware-test-impl.c
        )

target_link_libraries(vs-default-soft-crypto-test
        virgil-iot-sdk-tests
        vs-default-soft-provision
        )

#
#   Set additional compiler flags
#

if ("${CFLAGS_PLATFORM}" STREQUAL "")
    message("-- No CFLAGS_PLATFORM")
else()
    message("-- CFLAGS_PLATFORM = ${CFLAGS_PLATFORM}")
    string(REPLACE " " ";" CFLAGS_PLATFORM ${CFLAGS_PLATFORM})
endif()

target_compile_options(vs-default-soft-crypto-test
        PRIVATE -Wall -Werror ${CFLAGS_PLATFORM})

target_compile_definitions(vs-default-soft-crypto-test
        PRIVATE "VIRGIL_IOT_MCU_BUILD=$<BOOL:${VIRGIL_IOT_MCU_BUILD}>"
        )

#
#   Config path
#

#
#   Common include directories
#
target_include_directories(vs-default-soft-crypto-test
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>

        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:include>
        )

if(COMMAND add_clangformat)
    add_clangformat(vs-default-soft-crypto-test)
endif()
