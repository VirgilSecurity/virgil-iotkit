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

project(netif_plc_sim VERSION 0.1.0 LANGUAGES C)

set(NETIF_PLC_SIM
        src/hal/ti_netif_plc_sim.c
        src/hal/ti_hal.c
        src/hal/sdmp/ti_prvs_implementation.c
        )

add_library(${PROJECT_NAME}
        ${NETIF_PLC_SIM}
        )

target_link_libraries (${PROJECT_NAME} sdmp)

target_include_directories(${PROJECT_NAME}
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        )

set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-Wall -Werror -Wno-multichar")

# TODO: remove workaround with copying libs
set(INITIALIZER_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../lib)
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${INITIALIZER_LIB_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_BINARY_DIR}/ap/security-sdk/protocols/sdmp/libsdmp.a"
        ${INITIALIZER_LIB_DIR}/libsdmp.a
        COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_BINARY_DIR}/ap/security-sdk/tools/virgil-iot-initializer/c_libs/libnetif_plc_sim.a"
        ${INITIALIZER_LIB_DIR}/libnetif_plc_sim.a
        )
