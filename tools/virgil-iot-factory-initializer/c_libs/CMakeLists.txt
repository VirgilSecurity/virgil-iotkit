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

project(factory-initializer-hal VERSION 0.1.0 LANGUAGES C)

#
#   Network interfaces for Factory Inittializer
#
add_library(factory-initializer-hal)

#
#   Sources
#
target_sources(factory-initializer-hal
        PRIVATE

        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/initializer/hal/ti_netif_udp_bcast.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/initializer/hal/sdmp/ti_prvs_implementation.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/hal/ti_netif_udp_bcast.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hal/ti_hal.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hal/sdmp/ti_prvs_implementation.c
        )
#
#   Includes
#
target_include_directories(factory-initializer-hal
        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/../../../provision/include
        ${CMAKE_CURRENT_LIST_DIR}/../../../hsm/include
        )

#
#   Libraries
#
target_link_libraries(factory-initializer-hal
        PUBLIC
        sdmp-factory

        PRIVATE
        enable_pedantic_mode
        )