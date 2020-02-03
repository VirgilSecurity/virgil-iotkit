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

project(vs-tool-virgil-snapd VERSION 0.1.0 LANGUAGES Go C)

#
#   Check required CMake variables
#
if(NOT VIRGIL_IOT_DIRECTORY)
    message(FATAL_ERROR "[vs-tool-virgil-snapd] VIRGIL_IOT_DIRECTORY variable containing path to the Virgil IOT SDK source is not specified")
endif()

if(NOT VIRGIL_IOT_BINARY_DIRECTORY)
    message(FATAL_ERROR "[vs-tool-virgil-snapd] VIRGIL_IOT_BINARY_DIRECTORY variable containing path to the Virgil IOT SDK binary is not specified")
endif()

#
#   CFLAGS for CGO
#
set(CMAKE_CGO_CFLAGS
        ${CMAKE_CGO_CFLAGS}
        -I${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include
        -I${VIRGIL_IOT_DIRECTORY}/modules/provision/include
        -I${VIRGIL_IOT_DIRECTORY}/modules/crypto/converters/include
        -I${VIRGIL_IOT_DIRECTORY}/modules/crypto/secmodule/include
        -I${VIRGIL_IOT_DIRECTORY}/helpers/status_code/include
        -I${VIRGIL_IOT_DIRECTORY}/modules/firmware/include
        -I${VIRGIL_IOT_DIRECTORY}/modules/provision/trust_list/include
        -I${VIRGIL_IOT_DIRECTORY}/helpers/storage_hal/include
        -I${VIRGIL_IOT_DIRECTORY}/helpers/update/include
        -I${VIRGIL_IOT_DIRECTORY}/helpers/macros/include
        -I${VIRGIL_IOT_DIRECTORY}/modules/logger/include
        -I${VIRGIL_IOT_DIRECTORY}/config/pc
        -I${CMAKE_CURRENT_LIST_DIR}/../c-implementation/include
        -DINFO_CLIENT=1
        -DCFG_CLIENT=1
        )

#
#   LDFLAGS for CGO
#
set(CMAKE_CGO_LDFLAGS
        ${CMAKE_CGO_LDFLAGS}
        -L${VIRGIL_IOT_BINARY_DIRECTORY}/modules/protocols/snap
        -L${VIRGIL_IOT_BINARY_DIRECTORY}/modules/logger
        -L${VIRGIL_IOT_BINARY_DIRECTORY}/tools/c-implementation
        )

#
#   Virgil IoT Initializer
#
add_go_executable(vs-tool-virgil-snapd virgil-snapd tools-hal vs-module-logger)
