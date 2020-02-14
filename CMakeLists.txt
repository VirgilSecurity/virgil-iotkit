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

option(BIGENDIAN_64_BIT_BUILD "Build for MIPS 64 big endian" OFF)
option(BIGENDIAN_32_BIT_BUILD "Build for MIPS 32 big endian" OFF)

if(BIGENDIAN_64_BIT_BUILD)
    set(GO_DISABLE ON CACHE BOOL "Disable Go apps" FORCE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/sdk/cmake/mips64.toolchain.cmake")
    message("### CMAKE_TOOLCHAIN_FILE [${CMAKE_TOOLCHAIN_FILE}]")    
    message("### ENABLE BIGENDIAN_64_BIT")
endif()

if(BIGENDIAN_32_BIT_BUILD)
    set(GO_DISABLE ON CACHE BOOL "Disable Go apps" FORCE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/sdk/cmake/mips32.toolchain.cmake")
    message("### CMAKE_TOOLCHAIN_FILE [${CMAKE_TOOLCHAIN_FILE}]")        
    message("### ENABLE BIGENDIAN_32_BIT")    
endif()

message("### CMAKE_TOOLCHAIN_FILE [${CMAKE_TOOLCHAIN_FILE}]")    
message("### CMAKE_C_COMPILER   [${CMAKE_C_COMPILER}]")
message("### CMAKE_CXX_COMPILER  [${CMAKE_CXX_COMPILER}]")

project(iot-rpi VERSION 0.1.0 LANGUAGES C)


#
#   Build nix demo project
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/demo/nix)
