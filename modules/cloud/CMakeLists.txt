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

project(vs-module-cloud VERSION 0.1.0 LANGUAGES C)

add_library(vs-module-cloud)

target_sources(vs-module-cloud
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include/private/cloud_include.h
        ${CMAKE_CURRENT_LIST_DIR}/include/private/cloud_operations.h
        ${CMAKE_CURRENT_LIST_DIR}/include/private/cloud_parse_manifest.h

        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/cloud/base64.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/cloud/cloud.h

        ${CMAKE_CURRENT_LIST_DIR}/src/cloud_parse_manifest.c
        ${CMAKE_CURRENT_LIST_DIR}/src/cloud.c
        ${CMAKE_CURRENT_LIST_DIR}/src/base64.c
        ${CMAKE_CURRENT_LIST_DIR}/src/message_bin.c
        )

target_link_libraries(vs-module-cloud
        PUBLIC
        vs-json
        vs-module-firmware
        storage_hal
        )

target_include_directories(vs-module-cloud
        PRIVATE
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>

        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

install(TARGETS vs-module-cloud
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/virgil
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )

if(COMMAND add_clangformat)
    add_clangformat(vs-module-cloud)
endif()
