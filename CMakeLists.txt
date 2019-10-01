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

# ---------------------------------------------------------------------------
#   Enable Golang
# ---------------------------------------------------------------------------
if (NOT GO_DISABLE)
    include(cmake/golang.cmake)
    include(cmake/flags.cmake)
    set(VIRGIL_IOT_BINARY_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} CACHE STRING "Path to the Virgil IoT SDK binary")
    set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
endif()

# ---------------------------------------------------------------------------
#   Project
# ---------------------------------------------------------------------------
if (GO_DISABLE)
    project(virgil-iot-sdk VERSION 0.0.1 LANGUAGES C)
else()
    project(virgil-iot-sdk VERSION 0.0.1 LANGUAGES C Go)
endif()

# ---------------------------------------------------------------------------
#   Helper modules
# ---------------------------------------------------------------------------
include("cmake/clangformat.cmake")


# ---------------------------------------------------------------------------
#   Version options
# ---------------------------------------------------------------------------
set(VIRGIL_IOT_SDK_VERSION_LABEL "dev" CACHE STRING "Version label, i.e. beta, rc1.")

file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" "${virgil-iot-sdk-VERSION}")

if(VIRGIL_IOT_SDK_VERSION_LABEL)
    file(APPEND "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" "-${VIRGIL_IOT_SDK_VERSION_LABEL}")
endif()

file(APPEND "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" "\n")

# ---------------------------------------------------------------------------
#   Build options
# ---------------------------------------------------------------------------

#
#   Config path
#

if(NOT VIRGIL_IOT_CONFIG_DIRECTORY)
    message(FATAL_ERROR "[virgil-iot-sdk] VIRGIL_IOT_CONFIG_DIRECTORY variable containing path to the Virgil IOT SDK config is not specified")
else()
    message(STATUS "[virgil-iot-sdk] path to the Virgil IOT SDK config : ${VIRGIL_IOT_CONFIG_DIRECTORY}")
endif()

#
#   Target platform
#
option(VIRGIL_IOT_MCU_BUILD "Enable build for MCU" ON)

#
#   Additional HAL include paths
#
message(STATUS "[VIRGIL_IOT_SDK_HAL_INC_PATH] Additional paths to HAL : ${VIRGIL_IOT_SDK_HAL_INC_PATH}")

#
# Test
#
option(ENABLE_TESTING "On/Off integration tests." ON)
option(ENABLE_HEAVY_TESTS "On/Off execution of heavy tests." OFF)

#
# Features
#
option(VIRGIL_IOT_PROTOCOLS "Enable 'protocols'" ON)
option(VIRGIL_IOT_CLOUD "Enable 'cloud'" ON)
option(VIRGIL_IOT_PROVISION "Enable 'provision'" ON)
option(VIRGIL_IOT_SECBOX "Enable 'security box'" ON)
option(VIRGIL_IOT_UPDATE "Enable 'update'" OFF)



# ---------------------------------------------------------------------------
#   Dependencies / thirdparty libraries
# ---------------------------------------------------------------------------

#
#   Virgil crypto
#
set(ENABLE_TESTING OFF CACHE BOOL "On/Off integration tests." FORCE)
set(VIRGIL_C_TESTING OFF CACHE BOOL "On/Off C library integration tests." FORCE)
set(VIRGIL_LIB_PYTHIA OFF CACHE BOOL "Build 'pythia' library" FORCE)
set(VIRGIL_LIB_ED25519 OFF CACHE BOOL "Build 'ed25519' library" FORCE)
set(VIRGIL_LIB_RATCHET OFF CACHE BOOL "Build 'ratchet' library" FORCE)
set(VIRGIL_LIB_PHE OFF CACHE BOOL "Build 'phe' library" FORCE)
set(VIRGIL_INSTALL_HDRS  OFF CACHE BOOL "Install headers" FORCE)
set(VIRGIL_INSTALL_LIBS  OFF CACHE BOOL "Install libraries" FORCE)
set(VIRGIL_INSTALL_CMAKE OFF CACHE BOOL "Install CMake configuration files" FORCE)

# ---------------------------------------------------------------------------
#   Tools
# ---------------------------------------------------------------------------

if (NOT GO_DISABLE)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tools)
endif()


# ---------------------------------------------------------------------------
#   Features
# ---------------------------------------------------------------------------

#
#   Shared macros interface
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/macros)

#
#   Status codes
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/status_code)

#
#   Data storage hal interface
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/storage_hal)

#
#   jsmn
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ext/jsmn)

#
#   vs-json
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/json)

#
#   firmware
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/firmware)

#
#   update
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/update)

#
#   Logger
#
# TODO: Add Option to disable Logger
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/logger)

#
#   Cloud
#
if (VIRGIL_IOT_CLOUD)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/cloud)
endif()

#
#   Trust list
#
# TODO: Add Option to disable trust_list
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/trust_list)

#
#   Converters
#
if (NOT VIRGIL_IOT_MCU_BUILD)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/converters)
endif()
#
#   HSM
#
# TODO: Add Option to disable hsm
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/hsm)

#
#   Provision
#
# TODO: Add Option to disable hsm
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/provision)

#
#   Protocols
#
if (VIRGIL_IOT_PROTOCOLS)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/protocols)
endif()

#
#   Secbox
#
if (VIRGIL_IOT_SECBOX)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/secbox)
endif()

#
#   Tests
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
