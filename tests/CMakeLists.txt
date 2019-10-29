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

project(virgil-iot-sdk-tests VERSION 0.1.0 LANGUAGES C)

#
#  Tests library
#

add_library(virgil-iot-sdk-tests)

target_sources(virgil-iot-sdk-tests
        PRIVATE
        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tests/private/private_helpers.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tests/private/test_hl_keys_data.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tests/private/netif_test_impl.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tests/private/test_tl_data.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tests/helpers.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tests/tests.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/test_crypto.c
        ${CMAKE_CURRENT_LIST_DIR}/src/sdmp/sdmp_tests.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/aes.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/ecdh.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/ecdsa.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/hash.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/hmac.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/kdf.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/keypair.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/random.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/trust_list.c
        ${CMAKE_CURRENT_LIST_DIR}/src/secbox/secbox_test.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto/virgil_ecies.c
        ${CMAKE_CURRENT_LIST_DIR}/src/firmware/firmware_test.c
        ${CMAKE_CURRENT_LIST_DIR}/src/test_data/test_hl_keys_data.c
        ${CMAKE_CURRENT_LIST_DIR}/src/test_data/test_tl_data.c
        ${CMAKE_CURRENT_LIST_DIR}/src/helpers/crypto_helpers.c
        ${CMAKE_CURRENT_LIST_DIR}/src/helpers/netif_test_impl.c

        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/helpers/firmware_test_impl.c
        )

if (NOT VIRGIL_IOT_MCU_BUILD)
    target_sources(virgil-iot-sdk-tests
            PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/src/crypto/sign_converters.c
            ${CMAKE_CURRENT_LIST_DIR}/src/crypto/pubkeys_converters.c
            )
    target_link_libraries(virgil-iot-sdk-tests
            converters
            )
endif()

target_link_libraries(virgil-iot-sdk-tests
        vs-module-secbox
        vs-module-sdmp-factory
        vs-module-firmware
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

target_compile_options(virgil-iot-sdk-tests
        PRIVATE -Wall -Werror ${CFLAGS_PLATFORM})

target_compile_definitions(virgil-iot-sdk-tests
        PRIVATE "VIRGIL_IOT_MCU_BUILD=$<BOOL:${VIRGIL_IOT_MCU_BUILD}>"
        )

#
#   Config path
#

if(NOT VIRGIL_IOT_CONFIG_DIRECTORY)
    message(FATAL_ERROR "[virgil-iot-sdk-tests] VIRGIL_IOT_CONFIG_DIRECTORY variable containing path to the Virgil IOT SDK config is not specified")
else()
    message(STATUS "[virgil-iot-sdk-tests] path to the Virgil IOT SDK config : ${VIRGIL_IOT_CONFIG_DIRECTORY}")
endif()

#
#   Common include directories
#
target_include_directories(virgil-iot-sdk-tests
        PRIVATE
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<BUILD_INTERFACE:${VIRGIL_IOT_SDK_HAL_INC_PATH}>

        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:include>
        )

if(COMMAND add_clangformat)
    add_clangformat(virgil-iot-sdk-tests)
endif()
