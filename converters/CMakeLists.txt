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

project(converters VERSION 0.1.0 LANGUAGES C)

set(CONV_LIB converters)

#
#   Source code
#
set(CONV_SRC
        src/signature_converters.c
        src/pubkey_converters.c
        )

# Include and build external libraries
include (${CMAKE_CURRENT_SOURCE_DIR}/../cmake/virgil_depends.cmake)

set(VIRGIL_DEPENDS_CMAKE_ARGS "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}")
virgil_depends (
        PACKAGE_NAME "MbedTLS"
        CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs_ext/mbedtls"
        CMAKE_ARGS "${MBEDTLS_CMAKE_ARGS}"
)
virgil_find_package (MbedTLS 2.4)

#
#   Converters library
#
add_library(${CONV_LIB}
        SHARED
        ${CONV_SRC}
        )

#
#   Set additional compiler flags
#
if ("${CFLAGS_PLATFORM}" STREQUAL "")
    message("No CFLAGS_PLATFORM")
else()
    message("CFLAGS_PLATFORM = ${CFLAGS_PLATFORM}")
    string(REPLACE " " ";" CFLAGS_PLATFORM ${CFLAGS_PLATFORM})
endif()

target_compile_options(${PROJECT_NAME}
        PRIVATE -Wall -Werror ${CFLAGS_PLATFORM})

#
#   Config path
#

if(NOT VIRGIL_IOT_CONFIG_DIRECTORY)
    message(FATAL_ERROR "[converters] VIRGIL_IOT_CONFIG_DIRECTORY variable containing path to the Virgil IOT SDK config is not specified")
else()
    message(STATUS "[converters] path to the Virgil IOT SDK config : ${VIRGIL_IOT_CONFIG_DIRECTORY}")
endif()

target_compile_definitions(${PROJECT_NAME}
        PRIVATE "VIRGIL_IOT_MCU_BUILD=$<BOOL:${VIRGIL_IOT_MCU_BUILD}>"
        )

#
#   Common include directories
#
target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../logger/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../hsm/include>
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
        "$<BUILD_INTERFACE:${VIRGIL_IOT_SDK_HAL_INC_PATH}>"

        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:include>
        )

target_link_libraries (${PROJECT_NAME}
        PRIVATE
        mbedtls::mbedcrypto
        mbedtls::ed25519
        )

