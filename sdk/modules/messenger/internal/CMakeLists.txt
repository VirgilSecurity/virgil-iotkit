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
if (VIRGIL_IOT_MESSENGER_INTERNAL_XMPP)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../../ext/libstrophe libstrophe)
endif()

#
#   Virgil C++ SDK
#
find_library(VSCPPSDK_LIBRARY
        NAMES vscppsdk
        HINTS "${PLATFORM_LIBS_PATH}/lib"
        CMAKE_FIND_ROOT_PATH_BOTH
        )


target_sources(vs-messenger-internal
        PRIVATE

        # Headers
        $<$<BOOL:${VIRGIL_IOT_MESSENGER_INTERNAL_XMPP}>:${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/messenger/internal/enjabberd.h>
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/messenger/internal/virgil.h

        # Sources
        $<$<BOOL:${VIRGIL_IOT_MESSENGER_INTERNAL_XMPP}>:${CMAKE_CURRENT_LIST_DIR}/src/enjabberd.c>
        ${CMAKE_CURRENT_LIST_DIR}/src/virgil.cpp
        )

target_compile_definitions(vs-messenger-internal
        PUBLIC
        VS_INTERNAL_XMPP=${VIRGIL_IOT_MESSENGER_INTERNAL_XMPP}
        PRIVATE
        VS_BUILDING_DLL=1
        )

if (CMAKE_CROSSCOMPILING AND (NOT WIN32) )
    set(VS_DISABLE_SYS_CURL TRUE)
    if ((APPLE_PLATFORM STREQUAL "IOS") OR (APPLE_PLATFORM STREQUAL "IOS_SIM64"))
        set(VS_LINK_SSL_LIB FALSE)
        set(VS_LINK_SSL_FRAMEWORK TRUE)
    else()
        set(VS_LINK_SSL_LIB TRUE)
        set(VS_LINK_SSL_FRAMEWORK FALSE)
    endif()
else()
    set(VS_DISABLE_SYS_CURL FALSE)
    set(VS_LINK_SSL FALSE)
endif()

message ("VS_DISABLE_SYS_CURL = ${VS_DISABLE_SYS_CURL}")
message ("VS_LINK_SSL_LIB = ${VS_LINK_SSL_LIB}")
message ("VS_LINK_SSL_FRAMEWORK = ${VS_LINK_SSL_FRAMEWORK}")
message ("${PLATFORM_LIBS_PATH}/lib/libcurl.a")

target_link_libraries(vs-messenger-internal
        PUBLIC
        virgil-iot-status-code
        ${VSCPPSDK_LIBRARY}

        $<$<BOOL:${VIRGIL_IOT_MESSENGER_INTERNAL_XMPP}>:strophe>
        $<$<NOT:$<BOOL:${VS_DISABLE_SYS_CURL}>>:curl>

        $<$<BOOL:${VS_DISABLE_SYS_CURL}>:${PLATFORM_LIBS_PATH}/lib/libcurl.a>
        $<$<BOOL:${VS_LINK_SSL_LIB}>:${PLATFORM_LIBS_PATH}/lib/libssl.a>
        $<$<BOOL:${VS_LINK_SSL_LIB}>:${PLATFORM_LIBS_PATH}/lib/libcrypto.a>

        vs-messenger-crypto
        $<$<BOOL:${WIN32}>:kernel32>

        PRIVATE
        enable_pedantic_mode
        $<$<BOOL:${WIN32}>:-static-libgcc>
        $<$<BOOL:${WIN32}>:-static-libstdc++>
        $<$<BOOL:${WIN32}>:-static>
        )

if (VS_LINK_SSL_FRAMEWORK)
        target_link_libraries(vs-messenger-internal
                PUBLIC
                virgil-iot-status-code
                "-framework Security"
        )
endif()

target_include_directories(vs-messenger-internal
        PRIVATE
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
        $<BUILD_INTERFACE:${PLATFORM_LIBS_PATH}/include>
        $<BUILD_INTERFACE:${PLATFORM_LIBS_PATH}/include/virgil/crypto/common>
        $<BUILD_INTERFACE:${PLATFORM_LIBS_PATH}/include/virgil/crypto/foundation>
        $<BUILD_INTERFACE:${PLATFORM_LIBS_PATH}/include/virgil/sdk/core>
        $<$<NOT:$<BOOL:${VIRGIL_IOT_MESSENGER_INTERNAL_XMPP}>>:${OPENSSL_INCLUDE_DIR}>

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
