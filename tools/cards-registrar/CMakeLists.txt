#
# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (virgil-iot-registrar VERSION 1.0.0 LANGUAGES CXX)

# Enable C++14
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

file (GLOB_RECURSE SRC_LIST_SRC "src/*.cxx")
set (SRC_LIST ${SRC_LIST_BIN} ${SRC_LIST_SRC})

file (GLOB_RECURSE HEADER_LIST "include/*.h")

message (STATUS "PROJECT_NAME: " ${PROJECT_NAME})
message (STATUS "PROJECT_BINARY_DIR: " ${PROJECT_BINARY_DIR})
message (STATUS "PROJECT_SOURCE_DIR: " ${PROJECT_SOURCE_DIR})

message (STATUS "Source list: " ${SRC_LIST})

include_directories (${PROJECT_SOURCE_DIR}/include)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries (${PROJECT_NAME} virgil_sdk)

IF("${CMAKE_SYSTEM}" MATCHES "Linux")
    target_link_libraries (${PROJECT_NAME} pthread)
endif()
set_target_properties (${PROJECT_NAME} PROPERTIES OUTPUT_NAME "iot-registrar")
