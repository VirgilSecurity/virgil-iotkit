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

project(trust_list VERSION 0.1.0 LANGUAGES C)

#
#   Trust List library
#
add_library(trust_list)

#
#   Source code
#

target_sources(trust_list
        PRIVATE
        include/virgil/iot/trust_list/private/tl_operations.h
        include/virgil/iot/trust_list/tl_structs.h
        include/virgil/iot/trust_list/trust_list.h
        include/virgil/iot/trust_list/update_tl_interface.h

        src/tl_operations.c
        src/trust_list.c
        src/update_tl_interface.c
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

target_compile_options(trust_list
        PRIVATE -Wall -Werror ${CFLAGS_PLATFORM})

#
#   Config path
#

if(NOT VIRGIL_IOT_CONFIG_DIRECTORY)
    message(FATAL_ERROR "[trust_list] VIRGIL_IOT_CONFIG_DIRECTORY variable containing path to the Virgil IOT SDK config is not specified")
else()
    message(STATUS "[trust_list] path to the Virgil IOT SDK config : ${VIRGIL_IOT_CONFIG_DIRECTORY}")
endif()

target_compile_definitions(${PROJECT_NAME}
        PRIVATE "VIRGIL_IOT_MCU_BUILD=$<BOOL:${VIRGIL_IOT_MCU_BUILD}>"
        )

target_link_libraries(trust_list
        PUBLIC
        logger
        hsm
        macros
        provision
        storage_hal
        update
        )
#
#   Common include directories
#
target_include_directories(${PROJECT_NAME}
        PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
        "$<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>"

        PUBLIC
        "$<BUILD_INTERFACE:${VIRGIL_IOT_SDK_HAL_INC_PATH}>"

        INTERFACE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
        )

