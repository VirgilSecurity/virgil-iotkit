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

project (virgil-demo-soraa-lamp-initializer VERSION 1.0.0 LANGUAGES C CXX)

# Enable C++14
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

## Link with shared library if defined
set (USE_SDMP ON CACHE BOOL "Build for real usage. Use OFF to build test app.")
add_subdirectory (${PROJECT_SOURCE_DIR}/../../sdk/virgil-sdk-cpp virgil-sdk-cpp)

set (PLATFORM "osx" CACHE STRING "Platform type" FORCE)
set (ENABLE_TESTING OFF CACHE BOOL "Build test app" FORCE)
set (CRYPTO_MBEDTLS OFF CACHE BOOL "Build MBEDTLS crypto" FORCE)
set (CRYPTO_ATMEL ON CACHE BOOL "Build ATECC508A-based crypto" FORCE)
add_subdirectory (${PROJECT_SOURCE_DIR}/../../sdmp/SDMPKit/crypto crypto)
set_target_properties (virgil_mcu_crypto_mac PROPERTIES LINKER_LANGUAGE CXX)

file (GLOB_RECURSE SRC_LIST_SRC "src/*.cxx")
set (SRC_LIST ${SRC_LIST_BIN} ${SRC_LIST_SRC})

file (GLOB_RECURSE HEADER_LIST "include/*.h")

message (STATUS "PROJECT_BINARY_DIR: " ${PROJECT_BINARY_DIR})
message (STATUS "PROJECT_SOURCE_DIR: " ${PROJECT_SOURCE_DIR})

message (STATUS "Source list: " ${SRC_LIST})

include_directories (${PROJECT_SOURCE_DIR}/include)
include_directories (${PROJECT_SOURCE_DIR}/../../sdmp/SDMPKit/crypto/include)
include_directories (${PROJECT_SOURCE_DIR}/cmake-build-debug/depends/virgil_crypto/build/src/virgil_crypto-depends/lib/include)

# Add definitions
if (USE_SDMP)
    message (STATUS "Build SDMP code")
    add_definitions(-DUSE_SDMP)
else()
    message (STATUS "Build test code")
endif ()

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries (${PROJECT_NAME} virgil_sdk virgil_mcu_crypto_mac)
set_target_properties (${PROJECT_NAME} PROPERTIES OUTPUT_NAME "soraa-device-initializer")

if (APPLE)
    find_library (IOKIT_LIBRARY IOKit)
    find_library (CORE_FOUNDATION_LIBRARY CoreFoundation)

    target_link_libraries (${PROJECT_NAME} ${IOKIT_LIBRARY})
    target_link_libraries (${PROJECT_NAME} ${CORE_FOUNDATION_LIBRARY})
	add_definitions(-DFACTORY_INITIALIZER)
else()
    find_library (UDEV_LIBRARY udev)

    target_link_libraries (${PROJECT_NAME} ${UDEV_LIBRARY} m)
endif()
