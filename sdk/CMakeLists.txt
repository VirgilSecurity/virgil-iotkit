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

#
#   Version
#
set (PACKAGE_VERSION "0")
set (PACKAGE_VERSION_MAJOR "1")
set (PACKAGE_VERSION_MINOR "3")

include(GNUInstallDirs)

# ---------------------------------------------------------------------------
#   Check build type
# ---------------------------------------------------------------------------
#option(ANDROID_QT "Enable build for Android based on Qt library" OFF)

if (ANDROID_QT OR APPLE_PLATFORM)
    set(MOBILE_PLATFORM ON)
    set(GO_DISABLE ON)
    set(VIRGIL_IOT_DEFAULT_IMPL OFF)
endif()

# ---------------------------------------------------------------------------
#   Enable -mno-ms-bitfields for Windows and mingw32
# ---------------------------------------------------------------------------
if ("${OS}" STREQUAL "WINDOWS")
    add_compile_options(-mno-ms-bitfields)
endif()

# ---------------------------------------------------------------------------
#   Enable Golang
# ---------------------------------------------------------------------------
if(NOT GO_DISABLE)
    include(cmake/golang.cmake)
    include(cmake/flags.cmake)
    set(VIRGIL_IOT_BINARY_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} CACHE STRING "Path to the Virgil IoT SDK binary")
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake")
endif()

# ---------------------------------------------------------------------------
#   Project
# ---------------------------------------------------------------------------
if (GO_DISABLE)
    project(virgil-iot-sdk VERSION ${PACKAGE_VERSION}.${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR} LANGUAGES C)
else()
    project(virgil-iot-sdk VERSION ${PACKAGE_VERSION}.${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR} LANGUAGES C Go)
endif()
set(VIRGIL_IOT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR} CACHE STRING "Path to the Virgil IoT SDK")

# ---------------------------------------------------------------------------
#   Helper modules
# ---------------------------------------------------------------------------
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
include (clangformat)
include (TransitiveToolchainArgs)
include (helpers)

# ---------------------------------------------------------------------------
#   Version options
# ---------------------------------------------------------------------------
file(WRITE "${CMAKE_CURRENT_LIST_DIR}/VERSION" "${PACKAGE_VERSION}.${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR}")

file(APPEND "${CMAKE_CURRENT_LIST_DIR}/VERSION" "\n")

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
option(VIRGIL_IOT_MCU_BUILD "Disable build for MCU by default" OFF)

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
option(VIRGIL_IOT_MESSENGER "Enable 'messenger'" ON)
option(VIRGIL_IOT_MESSENGER_INTERNAL_XMPP "Enable internal XMPP client" ON)
option(VIRGIL_IOT_PROVISION "Enable 'provision'" ON)
option(VIRGIL_IOT_SECBOX "Enable 'security box'" ON)
option(VIRGIL_IOT_DEFAULT_IMPL "Enable Default implementations" ON)
option(VIRGIL_IOT_UPDATE "Enable 'update'" OFF)
option(VIRGIL_IOT_HIGH_LEVEL "Enable 'high level'" ON)

#
# Default crypto implementations
#
option(VIRGIL_IOT_DEFAULT_CRYPTO_VS_SOFT_SECMODULE "Enable default Virgil crypto soft SECMODULE implementation" ON)

#
# Default cloud implementations
#
option(VIRGIL_IOT_DEFAULT_CLOUD_CURL_HTTP "Enable default curl http implementation" ON)
option(VIRGIL_IOT_DEFAULT_CLOUD_MESSAGE_BIN_AWS "Enable default message bin aws implementation" ON)

# ---------------------------------------------------------------------------
#   Dependencies / thirdparty libraries
# ---------------------------------------------------------------------------
include (virgil_depends)


# Set external platform dependent libs dir
set(VIRGIL_PLATFORM "" CACHE STRING "")
set(VIRGIL_PLATFORM_LIBS_DIR "" CACHE STRING "")
set_libs_storage("${VIRGIL_PLATFORM}" "${VIRGIL_PLATFORM_LIBS_DIR}")

#
#   Tools
#
if (NOT GO_DISABLE)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tools)
endif()

#
#   Helpers
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/helpers)

#
#   Modules
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/modules)

#
#   Default implementations
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/default-impl)

#
#   High level
#
if (VIRGIL_IOT_HIGH_LEVEL)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/high-level)
endif()

#
#   Tests
#
if (NOT MOBILE_PLATFORM)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tests)
endif()

#
#   Documentation
#
add_custom_target(vs-iotkit-documentation
        COMMAND rm -fR docs/doxygen
        COMMAND mkdir -p docs/doxygen
        COMMAND doxygen
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})