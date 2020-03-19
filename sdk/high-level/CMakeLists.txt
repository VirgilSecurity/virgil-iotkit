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

project(vs-high-level VERSION 0.1.0 LANGUAGES C)

function(add_high_level _targetname _snap_lib)

    #
    #   High level library
    #
    add_library(${_targetname})

    target_sources(${_targetname}
            PRIVATE

            # Headers
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/high-level/high-level.h

            # Sources
            ${CMAKE_CURRENT_LIST_DIR}/src/high-level.c
            )

    #
    #   Common include directories
    #
    target_include_directories(${_targetname}
            PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
            $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
            "$<BUILD_INTERFACE:${VIRGIL_IOT_SDK_HAL_INC_PATH}>"

            INTERFACE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
            )

    #
    #   Link libraries
    #
    target_link_libraries(${_targetname}
            PUBLIC
            vs-module-provision
            vs-module-secbox
            ${_snap_lib}

            PRIVATE
            macros
            enable_pedantic_mode
            )

    if (COMMAND add_clangformat)
        add_clangformat(${_targetname})
    endif ()

    install(TARGETS ${_targetname}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            )

    install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/virgil
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            )

endfunction()

if (NOT MOBILE_PLATFORM)

    #
    #   High level For initializer
    #
    add_high_level("vs-high-level-initializer" "vs-module-snap-initializer")

    #
    #   High level For Thing
    #
    add_high_level("vs-high-level-thing" "vs-module-snap-thing")

    #
    #   High level For Gateway
    #
    add_high_level("vs-high-level-gateway" "vs-module-snap-gateway")
endif()
