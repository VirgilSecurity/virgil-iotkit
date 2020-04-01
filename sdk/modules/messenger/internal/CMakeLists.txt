#   Copyright (C) 2015-2020 Virgil Security Inc.
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

project(vs-messenger-internal VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(vs-messenger-internal SHARED)

#
#   libstrophe as dependency
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../../ext/libstrophe libstrophe)

#
#   Virgil C++ SDK
#
set (VSCPPSDK_PATH "${CMAKE_CURRENT_LIST_DIR}/../../../ext/virgil-sdk-cpp/cmake-build-host/release/installed/usr/local")
find_library(VSCPPSDK_LIBRARY
        NAMES vscppsdk
        HINTS "${VSCPPSDK_PATH}/lib"
        CMAKE_FIND_ROOT_PATH_BOTH
        )


target_sources(vs-messenger-internal
        PRIVATE

        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/messenger/internal/enjabberd.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/messenger/internal/virgil.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/enjabberd.c
        ${CMAKE_CURRENT_LIST_DIR}/src/virgil.cpp
        )

target_compile_definitions(vs-messenger-internal
        PRIVATE
        VS_BUILDING_DLL=1
        )

target_link_libraries(vs-messenger-internal
        PUBLIC
        virgil-iot-status-code
        ${VSCPPSDK_LIBRARY}
        strophe
        curl
        vs-messenger-crypto
        $<$<BOOL:${WIN32}>:kernel32>

        PRIVATE
        enable_pedantic_mode
        -static-libgcc -static-libstdc++ -static
        )

target_include_directories(vs-messenger-internal
        PRIVATE
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
        $<BUILD_INTERFACE:${VSCPPSDK_PATH}/include>

        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

set_target_properties(vs-messenger-internal
        PROPERTIES
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        )

install(TARGETS vs-messenger-internal
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/virgil
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )

if(COMMAND add_clangformat)
    add_clangformat(vs-messenger-internal)
endif()
