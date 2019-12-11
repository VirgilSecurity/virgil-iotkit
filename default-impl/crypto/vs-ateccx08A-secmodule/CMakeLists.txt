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

project(vs-default-ateccx08A-secmodule VERSION 0.1.0 LANGUAGES C)

add_library(vs-default-ateccx08A-secmodule)

target_sources(vs-default-ateccx08A-secmodule
        PRIVATE

        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/vs-ateccx08A-secmodule/vs-ateccx08A-secmodule.h
        ${CMAKE_CURRENT_LIST_DIR}/include/private/vs-ateccx08A-secmodule-internal.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/vs-secmodule-slots-config/vs-secmodule-slots-config.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/vs-ateccx08A-secmodule.c
        ${CMAKE_CURRENT_LIST_DIR}/src/ateccx08A-secmodule-crypto.c
        ${CMAKE_CURRENT_LIST_DIR}/src/ateccx08A-secmodule-keypair.c
        ${CMAKE_CURRENT_LIST_DIR}/src/ateccx08A-secmodule-slots.c
        ${CMAKE_CURRENT_LIST_DIR}/src/ateccx08A-secmodule-sha2.c

        )

#
#   Common include directories
#
target_include_directories(vs-default-ateccx08A-secmodule
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>

        INTERFACE
        $<INSTALL_INTERFACE:include>
        )

#
#   Link libraries
#
target_link_libraries(vs-default-ateccx08A-secmodule
        PUBLIC
        converters
        vs-module-secmodule
        storage_hal
        cryptoauth
        )

if(COMMAND add_clangformat)
    add_clangformat(vs-default-ateccx08A-secmodule)
endif()