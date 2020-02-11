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

project(vs-default-soft-secmodule VERSION 0.1.0 LANGUAGES C)

if(NOT VIRGIL_IOT_DIRECTORY)
    message(FATAL_ERROR "[vs-default-soft-secmodule] VIRGIL_IOT_DIRECTORY variable containing path to the Virgil IOT SDK source is not specified")
endif()

# Include and build external libraries
include (${VIRGIL_IOT_DIRECTORY}/cmake/virgil_depends.cmake)

set(VIRGIL_DEPENDS_CMAKE_ARGS "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}")
virgil_depends (
        PACKAGE_NAME "MbedTLS"
        CONFIG_DIR "${VIRGIL_IOT_DIRECTORY}/ext/mbedtls"
        CMAKE_ARGS "${MBEDTLS_CMAKE_ARGS}"
)
virgil_find_package (MbedTLS 2.4)

add_library(vs-default-soft-secmodule)

target_sources(vs-default-soft-secmodule
        PRIVATE

        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/vs-soft-secmodule/vs-soft-secmodule.h

        ${CMAKE_CURRENT_LIST_DIR}/include/private/vs-soft-secmodule-internal.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/vs-soft-secmodule.c
        ${CMAKE_CURRENT_LIST_DIR}/src/soft-secmodule-slots.c
        ${CMAKE_CURRENT_LIST_DIR}/src/soft-secmodule-sha2.c
        ${CMAKE_CURRENT_LIST_DIR}/src/soft-secmodule-crypto.c
        ${CMAKE_CURRENT_LIST_DIR}/src/soft-secmodule-keypair.c
        )

#
#   Common include directories
#
target_include_directories(vs-default-soft-secmodule
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>

        INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

install(TARGETS vs-default-soft-secmodule
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/virgil
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )

#
#   Link libraries
#
target_link_libraries(vs-default-soft-secmodule
        PRIVATE
        mbedtls::mbedcrypto
        mbedtls::ed25519
        converters

        PUBLIC
        vs-module-secmodule
        storage_hal
        )

if(COMMAND add_clangformat)
    add_clangformat(vs-default-soft-secmodule)
endif()


