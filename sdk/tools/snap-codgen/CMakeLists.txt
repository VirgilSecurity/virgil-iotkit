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

project(vs-tool-snap-codgen VERSION 0.1.0 LANGUAGES Go)

if(NOT VIRGIL_IOT_DIRECTORY)
    message(FATAL_ERROR "[vs-tool-snap-codgen] VIRGIL_IOT_DIRECTORY variable containing path to the Virgil IOT SDK source is not specified")
endif()

#
#   SNAP convert code generator
#
add_go_executable(vs-tool-snap-codgen snap-codgen)


#
# POST EXEC Generate convert code
#

set (SNAP_SRC_TYPES
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/snap-structs.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/prvs/prvs-structs.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/info/info-structs.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/msgr/msgr-structs.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/cfg/cfg-structs.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/info/info-private.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/fldt/fldt-private.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/msgr/msgr-private.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/cfg/cfg-private.h
        -i ${VIRGIL_IOT_DIRECTORY}/modules/provision/include/virgil/iot/provision/provision-structs.h
        -i ${VIRGIL_IOT_DIRECTORY}/helpers/update/include/virgil/iot/update/update.h
        )

add_custom_command(TARGET vs-tool-snap-codgen POST_BUILD
        COMMAND ${vs-tool-snap-codgen_BINARY_DIR}/snap-codgen -d ${PROJECT_SOURCE_DIR}/tmpl
                                                  ${SNAP_SRC_TYPES}
                                                  -oc ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/src/generated/snap_cvt.c
                                                  -oh ${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include/virgil/iot/protocols/snap/generated/snap_cvt.h
        COMMENT "Generate SNAP convert functions"
        )
