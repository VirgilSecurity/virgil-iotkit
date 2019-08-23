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

project(sdmp-codgen VERSION 0.1.0 LANGUAGES Go)

#
#   SDMP convert code generator
#
add_go_executable(sdmp-codgen)


#
# POST EXEC Generate convert code
#

set (SDMP_SRC_TYPES
        -i ${PROJECT_SOURCE_DIR}/../../protocols/sdmp/include/virgil/iot/protocols/sdmp/sdmp_structs.h
        -i ${PROJECT_SOURCE_DIR}/../../protocols/sdmp/include/virgil/iot/protocols/sdmp/prvs.h
        )

add_custom_command(TARGET sdmp-codgen POST_BUILD
    COMMAND ${sdmp-codgen_BINARY_DIR}/sdmp-codgen -d ${PROJECT_SOURCE_DIR}/tmpl 
                                                  ${SDMP_SRC_TYPES} 
                                                  -oc ${PROJECT_SOURCE_DIR}/../../protocols/sdmp/src/generated/sdmp_cvt.c 
                                                  -oh ${PROJECT_SOURCE_DIR}/../../protocols/sdmp/include/virgil/iot/protocols/sdmp/generated/sdmp_cvt.h
    COMMENT "Generate SDMP convert function"
)
