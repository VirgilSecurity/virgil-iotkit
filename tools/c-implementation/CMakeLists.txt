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

project(tools-hal VERSION 0.1.0 LANGUAGES C)

if(NOT VIRGIL_IOT_DIRECTORY)
    message(FATAL_ERROR "[c-implementation] VIRGIL_IOT_DIRECTORY variable containing path to the Virgil IOT SDK source is not specified")
endif()

#
#   Network interfaces for Factory Inittializer
#
add_library(tools-hal)

#
#   Sources
#
target_sources(tools-hal
        PRIVATE

        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tools/hal/ti_netif_udp_bcast.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tools/hal/snap/ti_prvs_impl.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/tools/helpers/ti_wait_functionality.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/hal/ti_netif_udp_bcast.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hal/ti_hal.c
        ${CMAKE_CURRENT_LIST_DIR}/src/helpers/ti_wait_functionality.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hal/snap/ti_prvs_impl.c
        )
#
#   Includes
#
target_include_directories(tools-hal
        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${VIRGIL_IOT_DIRECTORY}/modules/provision/include
        ${VIRGIL_IOT_DIRECTORY}/modules/crypto/secmodule/include

        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

#
#   Libraries
#
target_link_libraries(tools-hal
        PUBLIC
        vs-module-snap-factory

        PRIVATE
        enable_pedantic_mode
        )

install(TARGETS tools-hal
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/virgil
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )

if(COMMAND add_clangformat)
    add_clangformat(tools-hal)
endif()
