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

project(thing VERSION 0.1.0 LANGUAGES C)

#
#	Gateway application
#
add_executable(thing)

#
#	Header/Source files
#
target_sources(thing
        PRIVATE
        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/main.c
		)

#
#	Definitions
#

target_compile_definitions(thing
        PRIVATE
        TEST_UPDATE_MESSAGE="${TEST_UPDATE_MESSAGE}"
		THING_MANUFACTURE_ID="${THING_MANUFACTURE}"
		THING_DEVICE_MODEL="${THING_MODEL}"
		SIMULATOR=$<BOOL:${GATEWAY_SIMULATOR}>
        SIM_FETCH_FIRMWARE=$<BOOL:${SIM_FETCH_FIRMWARE}>
        )

#
#   Include directories
#
target_include_directories(thing
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        )

#
#	Compile options
#
target_compile_options(thing
		PRIVATE
		$<$<NOT:$<BOOL:${APPLE}>>:-Wno-format-truncation>
		)

#
#	Link libraries
#
target_link_libraries(thing
        PRIVATE

        $<$<NOT:$<BOOL:${APPLE}>>:-Wl,--whole-archive>
		nix-common
		nix-common-firmware
		$<$<NOT:$<BOOL:${APPLE}>>:-Wl,--no-whole-archive>

		vs-high-level-thing

		enable_sanitizers
        enable_pedantic_mode
        )

#
# Create a signed firmware image
#
if(NOT GO_DISABLE)
	if(NOT THING_APP_FILE_SIZE)
		set(THING_APP_FILE_SIZE "2097152" CACHE STRING "Full thing application file size")
	endif()

	if(NOT THING_APP_CHUNK_SIZE)
		set(THING_APP_CHUNK_SIZE "65535" CACHE STRING "Thing application chunk size")
	endif()

	include(signFirmware)

	sign_firmware(thing-signed
			${VIRGIL_FIRMWARE_SIGNER_CONFIG_FILE_PATH}
			${CMAKE_BINARY_DIR}/thing/thing
			${THING_APP_FILE_SIZE}
			${APP_VERSION}
			${THING_MANUFACTURE}
			${THING_MODEL}
			${THING_APP_CHUNK_SIZE}
			APPL)

	add_dependencies(thing-signed vs-tool-virgil-firmware-signer thing)

endif()

if(COMMAND add_clangformat)
	add_clangformat(thing)
endif()

install(TARGETS thing
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	)
