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

project(sdmp VERSION 0.1.0 LANGUAGES C)

function(add_sdmp _for_factory)

    if (_for_factory)
        set (_targetname "sdmp-factory")
    else()
        set (_targetname "sdmp")
    endif()

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
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/sdmp_structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/sdmp_private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/prvs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/fldt_private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/fldt_client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/fldt_server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/sdmp/info.h

            ${CMAKE_CURRENT_LIST_DIR}/src/sdmp.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/fldt.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/fldt_client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/fldt_server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/prvs.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/info.c
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
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"

            PRIVATE
            # TODO: FIX PVS
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../../trust_list/include>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../../hsm/include>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../../../inc>"
            "$<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>"
            )

    #
    #   Add definitions
    #
    target_compile_definitions(${_targetname}
            PUBLIC
            "VS_SDMP_FACTORY=${_for_factory}"
            )

    #
    #   Link libraries
    #
    target_link_libraries(${_targetname}
            PUBLIC
            virgil-iot-status-code
            logger
            provision
            update
            firmware
            $<$<NOT:$<BOOL:${_for_factory}>>:hsm>
            $<$<NOT:$<BOOL:${_for_factory}>>:trust_list>

            PRIVATE
            macros
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
add_sdmp(1)

#
#   SDMP For common usage
#
add_sdmp(0)