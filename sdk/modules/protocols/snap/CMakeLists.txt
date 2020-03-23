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

project(vs-module-snap VERSION 0.1.0 LANGUAGES C)

function(add_snap _targetname _firmware_update _definitions)

    #
    #   SNAP library
    #

    add_library(${_targetname})

    #
    #   Sources
    #

    target_sources(${_targetname}
            PRIVATE

            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/snap-structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/private/snap-private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/fldt/fldt-private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/fldt/fldt-client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/fldt/fldt-server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/info/info-server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/info/info-client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/info/info-private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/info/info-structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/prvs/prvs-server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/prvs/prvs-client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/prvs/prvs-structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/cfg/cfg-server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/cfg/cfg-client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/cfg/cfg-private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/cfg/cfg-structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/msgr/msgr-server.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/msgr/msgr-client.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/msgr/msgr-private.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/msgr/msgr-structs.h
            ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/protocols/snap/generated/snap_cvt.h

            ${CMAKE_CURRENT_LIST_DIR}/src/snap.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/fldt/fldt-client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/fldt/fldt-server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/prvs/prvs-server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/prvs/prvs-client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/info/info-server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/info/info-client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/cfg/cfg-server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/cfg/cfg-client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/msgr/msgr-server.c
            ${CMAKE_CURRENT_LIST_DIR}/src/services/msgr/msgr-client.c
            ${CMAKE_CURRENT_LIST_DIR}/src/generated/snap_cvt.c
            )

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
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>

            PRIVATE
            $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
            )
    install(TARGETS ${_targetname}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            )

    install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/virgil
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            )

    #
    #   Add definitions
    #
    if ("${_definitions}" STREQUAL "")
        message("-- No _definitions for SNAP target ${_targetname}")
    else()
        message("-- SNAP_DEFINITIONS for ${_targetname} = ${_definitions}")
        string(REPLACE " " ";" SNAP_DEFINITIONS ${_definitions})
    endif()

    target_compile_definitions(${_targetname}
            PUBLIC
            ${SNAP_DEFINITIONS}
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
    #   Format code
    #
    if (COMMAND add_clangformat)
        add_clangformat(${_targetname})
    endif ()

endfunction()

#
#   SNAP For factory purposes
#
add_snap("vs-module-snap-factory" 1 "PRVS_CLIENT=1 INFO_CLIENT=1 CFG_CLIENT=1")

if (NOT MOBILE_PLATFORM)

    #
    #   SNAP Devices initializer
    #
    add_snap("vs-module-snap-initializer" 1 "PRVS_SERVER=1 INFO_SERVER=1 CFG_SERVER=1")

    #
    #   SNAP For Thing
    #
    add_snap("vs-module-snap-thing" 1 "FLDT_CLIENT=1 INFO_SERVER=1 CFG_SERVER=1 MSGR_SERVER=1")

    #
    #   SNAP For Gateway
    #
    add_snap("vs-module-snap-gateway" 1 "FLDT_SERVER=1 INFO_SERVER=1 CFG_SERVER=1 MSGR_CLIENT=1")
endif()

#
#   SNAP For Control
#
add_snap("vs-module-snap-control" 0 "INFO_CLIENT=1 CFG_CLIENT=1")