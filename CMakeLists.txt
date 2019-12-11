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

include(GNUInstallDirs)

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
    project(virgil-iot-sdk VERSION 0.0.1 LANGUAGES C)
else()
    project(virgil-iot-sdk VERSION 0.0.1 LANGUAGES C Go)
endif()
set(VIRGIL_IOT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR} CACHE STRING "Path to the Virgil IoT SDK")

# ---------------------------------------------------------------------------
#   Helper modules
# ---------------------------------------------------------------------------
include(${CMAKE_CURRENT_LIST_DIR}/cmake/clangformat.cmake)


# ---------------------------------------------------------------------------
#   Version options
# ---------------------------------------------------------------------------
set(VIRGIL_IOT_SDK_VERSION_LABEL "dev" CACHE STRING "Version label, i.e. beta, rc1.")

file(WRITE "${CMAKE_CURRENT_LIST_DIR}/VERSION" "${virgil-iot-sdk-VERSION}")

if(VIRGIL_IOT_SDK_VERSION_LABEL)
    file(APPEND "${CMAKE_CURRENT_LIST_DIR}/VERSION" "-${VIRGIL_IOT_SDK_VERSION_LABEL}")
endif()

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
option(VIRGIL_IOT_PROVISION "Enable 'provision'" ON)
option(VIRGIL_IOT_SECBOX "Enable 'security box'" ON)
option(VIRGIL_IOT_UPDATE "Enable 'update'" OFF)
# default implementations
option(VIRGIL_IOT_DEFAULT_IMPL "Enable Default implementations" OFF)
option(VIRGIL_IOT_DEFAULT_SECMODULE_IMPL "Enable Default secmodule implementations" OFF)

if (VIRGIL_IOT_DEFAULT_IMPL)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/default-impl)

    include(${CMAKE_CURRENT_LIST_DIR}/cmake/CheckEnabledDefaultOptions.cmake)

    if (VIRGIL_IOT_DEFAULT_SECMODULE_IMPL)

        #
        # Default secmodule implementations
        #
        option(VIRGIL_IOT_DEFAULT_VS_SOFT_SECMODULE "Enable default Virgil crypto soft SECMODULE implementation" OFF)
        option(VIRGIL_IOT_DEFAULT_VS_ATECCx08A_SECMODULE "Enable default Virgil crypto ATECCx08A SECMODULE implementation" OFF)

        check_enabled_options("secmodule default impl" VIRGIL_IOT_DEFAULT_VS_SOFT_SECMODULE VIRGIL_IOT_DEFAULT_VS_ATECCx08A_SECMODULE)

        if(VIRGIL_IOT_DEFAULT_VS_SOFT_SECMODULE)
            # set a path to directory where the secmodule can find a header file with slot configuration
            set(VS_SECMODULE_SLOTS_CONFIG_DIRECTORY
                    "${CMAKE_CURRENT_LIST_DIR}/default-impl/crypto/vs-soft-secmodule/include/virgil/iot/vs-secmodule-slots-config"
                    CACHE STRING "Path to the slots config file")
        endif()

        if(VIRGIL_IOT_DEFAULT_VS_ATECCx08A_SECMODULE)
            # set a path to directory where the secmodule can find a header file with slot configuration
            set(VS_SECMODULE_SLOTS_CONFIG_DIRECTORY
                    "${CMAKE_CURRENT_LIST_DIR}/default-impl/crypto/vs-ateccx08A-secmodule/include/virgil/iot/vs-secmodule-slots-config"
                    CACHE STRING "Path to the slots config file")

            #
            #   Microchip cryptoauth library for ATECCx08 hsm devices
            #
            if (VIRGIL_IOT_MCU_BUILD)
                set(ATCA_HAL_I2C ON CACHE BOOL "Include the I2C Hal Driver - Linux & MCU only" FORCE)
            else()
                set(ATCA_HAL_KIT_HID ON CACHE BOOL "Include the HID HAL Driver" FORCE)
            endif ()
            set(ATCA_BUILD_SHARED_LIBS OFF CACHE BOOL "Build CryptoAuthLib as shared library" FORCE)
            add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/ext/microchip-hsm)

        endif()
    endif ()

    #
    # Default cloud implementations
    #
    option(VIRGIL_IOT_DEFAULT_CLOUD_CURL_HTTP "Enable default curl http implementation" OFF)
    option(VIRGIL_IOT_DEFAULT_CLOUD_MESSAGE_BIN_AWS "Enable default message bin aws implementation" OFF)

        #
        #   aws-sdk
        #
        if(VIRGIL_IOT_DEFAULT_CLOUD_MESSAGE_BIN_AWS)
            add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ext/aws-sdk)
        endif()
endif ()

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
#   Tests
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tests)

#
#   Documentation
#
add_custom_target(vs-iotkit-documentation
        COMMAND rm -fR docs/doxygen
        COMMAND mkdir -p docs/doxygen
        COMMAND doxygen
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})