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

project(vs-module-sdmp VERSION 0.1.0 LANGUAGES C)

function(add_sdmp _targetname _firmware_update _definitions)

    #
    #   SDMP library
    #

    add_library(${_targetname})

    #
    #   Sources
    #

    target_sources(${_targetname}
            PRIVATE

            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/sdmp-structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/private/sdmp-private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/fldt/fldt-private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/fldt/fldt-client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/fldt/fldt-server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/info/info-server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/info/info-client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/info/info-private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/info/info-structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/prvs/prvs-server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/prvs/prvs-client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/prvs/prvs-structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/generated/sdmp_cvt.h

            ${CMAKE_CURRENT_LIST_DIR}/src/sdmp.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/fldt/fldt-client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/fldt/fldt-server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/prvs/prvs-server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/prvs/prvs-client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/info/info-server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/info/info-client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/generated/sdmp_cvt.c
            )

    #
    #   -Wall -Werror
    #
    set_target_properties(${_targetname} PROPERTIES COMPILE_FLAGS "-Wall -Werror")

    #
    #   Config path
    #

    if (NOT VIRGIL_IOT_CONFIG_DIRECTORY)
        message(FATAL_ERROR "[protocols] VIRGIL_IOT_CONFIG_DIRECTORY variable containing path to the Virgil IOT SDK config is not specified")
    endif ()

    #
    #   Common include directories
    #
    target_include_directories(${_targetname}
            PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>

            PRIVATE
            $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
            )

    #
    #   Add definitions
    #
    if ("${_definitions}" STREQUAL "")
        message("-- No _definitions for SDMP target ${_targetname}")
    else()
        message("-- SDMP_DEFINITIONS for ${_targetname} = ${_definitions}")
        string(REPLACE " " ";" SDMP_DEFINITIONS ${_definitions})
    endif()

    target_compile_definitions(${_targetname}
            PUBLIC
            ${SDMP_DEFINITIONS}
            )

    #
    #   Link libraries
    #
    target_link_libraries(${_targetname}
            PUBLIC
            virgil-iot-status-code
            vs-module-provision
            $<$<BOOL:${_firmware_update}>:vs-module-firmware>

            PRIVATE
            macros
            enable_pedantic_mode
            )

    #
    # Format code
    #
    if (COMMAND add_clangformat)
        add_clangformat(${_targetname})
    endif ()

endfunction()

#
#   SDMP For factory purposes
#
add_sdmp("vs-module-sdmp-factory" 1 "PRVS_CLIENT=1 INFO_CLIENT=1")

#
#   SDMP Devices initializer
#
add_sdmp("vs-module-sdmp-initializer" 0 "PRVS_SERVER=1")

#
#   SDMP For Thing
#
add_sdmp("vs-module-sdmp-thing" 1 "FLDT_CLIENT=1 INFO_SERVER=1")

#
#   SDMP For Gateway
#
add_sdmp("vs-module-sdmp-gateway" 1 "FLDT_SERVER=1 INFO_SERVER=1")

#
#   SDMP For Test
#
add_sdmp("vs-module-sdmp-test" 1 "FLDT_SERVER=1 FLDT_CLIENT=1")
