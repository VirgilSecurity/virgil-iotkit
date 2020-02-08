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

#------------------------------------------------------------------------------
#   Settings
#------------------------------------------------------------------------------
option(GO_DISABLE "Disable Go apps" OFF)
option(BIGENDIAN_64_BIT_BUILD "Build for MIPS 64 big endian" OFF)
option(BIGENDIAN_32_BIT_BUILD "Build for MIPS 32 big endian" OFF)
option(GATEWAY_SIMULATOR "On/Off code for simulator." ON)
option(VIRGIL_IOT_MCU_BUILD "Enable build for MCU" OFF)

# Sanitizers
option(USE_ASAN "On/Off Address sanitizer." OFF)
option(USE_MSAN "On/Off Memory sanitizer." OFF)
option(USE_LSAN "On/Off Leak memory sanitizer." OFF)
option(USE_UBSAN "On/Off Undefined behavior sanitizer." OFF)
option(USE_TSAN "On/Off Thread sanitizer." OFF)

if(BIGENDIAN_64_BIT_BUILD)
    set(GO_DISABLE ON CACHE BOOL "Disable Go apps" FORCE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/cmake/mips64.toolchain.cmake")
endif()

if(BIGENDIAN_32_BIT_BUILD)
    set(GO_DISABLE ON CACHE BOOL "Disable Go apps" FORCE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/cmake/mips32.toolchain.cmake")
endif()


#------------------------------------------------------------------------------
#   Includes
#------------------------------------------------------------------------------

# Clang format
include(${CMAKE_CURRENT_LIST_DIR}/ext/virgil-iot-sdk/cmake/clangformat.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/helpers.cmake)


#
# Manufacture and model options
#
create_text_option(GATEWAY_MANUFACTURE "16" "VRGL" "Gateway manufacture code")
create_text_option(GATEWAY_MODEL "4" "Cf01" "Gateway model code")
create_text_option(THING_MANUFACTURE "16" "VIRGIL" "Thing manufacture code")
create_text_option(THING_MODEL "4" "MCU1" "Thing model code")

#
# Project version options
#
create_text_option(APP_MAJOR "3" "0" "Application major version")
create_text_option(APP_MINOR "3" "0" "Application minor version")
create_text_option(APP_PATCH "3" "0" "Application patch version")
create_text_option(APP_BUILD "10" "33333" "Application build version")
set(APP_VERSION "${APP_MAJOR}.${APP_MINOR}.${APP_PATCH}.${APP_BUILD}")

#
# Path to config file for a firmware signer
#
if(NOT VIRGIL_FIRMWARE_SIGNER_CONFIG_FILE_PATH AND NOT GO_DISABLE)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/signer-config/signer-template-config.json" "[{\"path\": \"${CMAKE_CURRENT_LIST_DIR}/dummy-keys/dummy-auth1.key\", \"key_type\": 1}, {\"path\": \"${CMAKE_CURRENT_LIST_DIR}/dummy-keys/dummy-firmware1.key\", \"key_type\": 3}]")
    set(VIRGIL_FIRMWARE_SIGNER_CONFIG_FILE_PATH "${CMAKE_CURRENT_BINARY_DIR}/signer-config/signer-template-config.json")
    message(WARNING "VIRGIL_FIRMWARE_SIGNER_CONFIG_FILE_PATH is not defined. Use default config with dummy keys")
endif()

option(GATEWAY_SIMULATOR "On/Off Test message" OFF)


#------------------------------------------------------------------------------
#   Golang
#------------------------------------------------------------------------------
if(NOT GO_DISABLE)
    include(${CMAKE_CURRENT_LIST_DIR}/cmake/golang.cmake)
    include(${CMAKE_CURRENT_LIST_DIR}/cmake/flags.cmake)
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake")
endif()

#------------------------------------------------------------------------------
#   Setup project
#------------------------------------------------------------------------------
if(GO_DISABLE)
    project(iot-rpi VERSION 0.1.0 LANGUAGES C)
else()
    project(iot-rpi VERSION 0.1.0 LANGUAGES C Go)
endif()

#
#   Virgil IoT SDK
#
set(VIRGIL_IOT_CONFIG_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/ext/virgil-iot-sdk/config/pc CACHE STRING "Path to the Virgil IoT SDK configuration")
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/ext/virgil-iot-sdk)

#
#   Common code library
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/common)

#
#   Initalizers for Gateway and Thing
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/initializer)

#
#   Gateway application
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/gateway)

#
#   Thing application
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/thing)

#
#   Bootloader application
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/bootloader)

#
#   Unit tests
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tests)
