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

project(virgil-signer VERSION 0.1.0 LANGUAGES Go)

#
# CFLAGS for CGO
#
set(CMAKE_CGO_CFLAGS
        ${CMAKE_CGO_CFLAGS}
        -I${CMAKE_CURRENT_LIST_DIR}/../../converters/include
        -I${CMAKE_CURRENT_LIST_DIR}/../../hsm/include
    )

#
# LDFLAGS for CGO
#
set(CMAKE_CGO_LDFLAGS
        ${CMAKE_CGO_LDFLAGS}
        -L${CMAKE_BINARY_DIR}/ap/security-sdk/converters
    )

#
# Workaround target
# Copies mbedtls libs to /lib folder in order to avoid conflicts with virgil_crypto mbedtls
#
set(INITIALIZER_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/lib)
set(LIBS_TARGET ${PROJECT_NAME}-libs)
add_custom_target(${LIBS_TARGET}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${INITIALIZER_LIB_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_BINARY_DIR}/depends/installed/lib/libmbedcrypto.a"
        ${INITIALIZER_LIB_DIR}/
        COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_BINARY_DIR}/depends/installed/lib/libed25519.a"
        ${INITIALIZER_LIB_DIR}
        )

#
#   Virgil Signer
#
add_go_executable(virgil-firmware-signer converters ${LIBS_TARGET})
