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

project(bootloader VERSION 0.1.0 LANGUAGES C)

#
#   Function to create targets for bootloaders
#
function(bootloader_executable _is_gateway _manufacture _model)
    #
    #	Prepare _targetname
    #
    if(${_is_gateway})
        set(_targetname "gateway-bootloader")
    else()
        set(_targetname "thing-bootloader")
    endif()

    #
    #	Bootloader target
    #
    add_executable(${_targetname})

    #
    #	Header/Source files
    #
    target_sources(${_targetname}
            PRIVATE
            # Sources
            ${CMAKE_CURRENT_LIST_DIR}/src/main.c
            )
    #
    #	Link libraries
    #
    target_link_libraries(${_targetname}
            PRIVATE

            $<$<NOT:$<BOOL:${APPLE}>>:-Wl,--whole-archive>
            nix-common
            nix-common-firmware
            $<$<NOT:$<BOOL:${APPLE}>>:-Wl,--no-whole-archive>

            vs-module-firmware
            virgil-iot-status-code

            enable_sanitizers
            enable_pedantic_mode
            )

    #
    #	Definitions
    #
    target_compile_definitions(${_targetname}
            PRIVATE
            GATEWAY=${_is_gateway}
            MANUFACTURE_ID="${_manufacture}"
            DEVICE_MODEL="${_model}"
            )
    #
    # Format code
    #
    if(COMMAND add_clangformat)
        add_clangformat(${_targetname})
    endif()

    install(TARGETS ${_targetname}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            )

endfunction()


#
#	Gateway bootloader
#
set(GATEWAY_MODE 1)
bootloader_executable(${GATEWAY_MODE} ${GATEWAY_MANUFACTURE} ${GATEWAY_MODEL})


#
#	Thing bootloader
#
set(THING_MODE 0)
bootloader_executable(${THING_MODE} ${THING_MANUFACTURE} ${THING_MODEL})
