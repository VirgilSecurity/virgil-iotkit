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

project(vs-module-hsm VERSION 0.1.0 LANGUAGES C)

add_library(vs-module-hsm)

target_sources(vs-module-hsm
        PRIVATE
        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/hsm/hsm.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/hsm/hsm_helpers.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/hsm/devices/hsm_atecc_508a.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/hsm/devices/hsm_atecc_608a.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/hsm/devices/hsm_custom.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/hsm/devices/hsm_iotelic.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/hsm/devices/hsm_iotelic.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm_helpers.c
        ${CMAKE_CURRENT_LIST_DIR}/src/asn1-cryptogram.c
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

target_compile_options(vs-module-hsm
        PRIVATE -Wall -Werror ${CFLAGS_PLATFORM})

#
#   Config path
#

if(NOT VIRGIL_IOT_CONFIG_DIRECTORY)
    message(FATAL_ERROR "[vs-module-hsm] VIRGIL_IOT_CONFIG_DIRECTORY variable containing path to the Virgil IOT SDK config is not specified")
else()
    message(STATUS "[vs-module-hsm] path to the Virgil IOT SDK config : ${VIRGIL_IOT_CONFIG_DIRECTORY}")
endif()

target_compile_definitions(vs-module-hsm
        PRIVATE "VIRGIL_IOT_MCU_BUILD=$<BOOL:${VIRGIL_IOT_MCU_BUILD}>"
        )

target_link_libraries(vs-module-hsm
        PUBLIC
        macros
        virgil-iot-status-code
        )
#
#   Common include directories
#
target_include_directories(vs-module-hsm
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
        $<BUILD_INTERFACE:${VIRGIL_IOT_SDK_HAL_INC_PATH}>

        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:include>
        )

if(COMMAND add_clangformat)
    add_clangformat(vs-module-hsm)
endif()

