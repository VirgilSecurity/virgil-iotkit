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

project(gateway VERSION 0.1.0 LANGUAGES C)

#
#	Gateway application
#
add_executable(gateway)

#
#	Header/Source files
#
target_sources(gateway
        PRIVATE

        # Headers
		${CMAKE_CURRENT_LIST_DIR}/include/event-flags.h
		${CMAKE_CURRENT_LIST_DIR}/include/threads/main-thread.h
		${CMAKE_CURRENT_LIST_DIR}/include/threads/message-bin-thread.h
		${CMAKE_CURRENT_LIST_DIR}/include/threads/file-download-thread.h
		${CMAKE_CURRENT_LIST_DIR}/include/netif/curl-websocket.h
		${CMAKE_CURRENT_LIST_DIR}/include/netif/netif-websocket.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/main.c
		${CMAKE_CURRENT_LIST_DIR}/src/threads/message-bin-thread.c
		${CMAKE_CURRENT_LIST_DIR}/src/threads/main-thread.c
		${CMAKE_CURRENT_LIST_DIR}/src/threads/file-download-thread.c
		${CMAKE_CURRENT_LIST_DIR}/src/netif/curl-websocket.c
		${CMAKE_CURRENT_LIST_DIR}/src/netif/curl-websocket-utils.c
		${CMAKE_CURRENT_LIST_DIR}/src/netif/netif-websocket.c
        )

#
#	Definitions
#
target_compile_definitions(gateway
        PRIVATE
        TEST_UPDATE_MESSAGE="${TEST_UPDATE_MESSAGE}"
        SIMULATOR=$<BOOL:${GATEWAY_SIMULATOR}>
        SIM_FETCH_FIRMWARE=$<BOOL:${SIM_FETCH_FIRMWARE}>
		GATEWAY=1
		GW_MANUFACTURE_ID="${GATEWAY_MANUFACTURE}"
		GW_DEVICE_MODEL="${GATEWAY_MODEL}"
        )

#
#   Include directories
#
target_include_directories(gateway
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        )


#
#	Compile options
#
target_compile_options(gateway
        PRIVATE
        $<$<NOT:$<BOOL:${APPLE}>>:-Wno-format-truncation>
        )

#
#	Link libraries
#
target_link_libraries(gateway
        PRIVATE

		$<$<NOT:$<BOOL:${APPLE}>>:-Wl,--whole-archive>
		nix-common
		nix-common-firmware
		$<$<NOT:$<BOOL:${APPLE}>>:-Wl,--no-whole-archive>

		vs-default-curl-http
		vs-default-aws-message-bin
		vs-module-cloud
		vs-module-firmware
		vs-high-level-gateway

		enable_sanitizers
        enable_pedantic_mode
        )

#
# Create a signed firmware image
#
if(NOT GO_DISABLE)
	if(NOT GW_APP_FILE_SIZE)
		set(GW_APP_FILE_SIZE "2097152" CACHE STRING "Full gateway application file size")
	endif()

	if(NOT GW_APP_CHUNK_SIZE)
		set(GW_APP_CHUNK_SIZE "65535" CACHE STRING "Gateway application chunk size")
	endif()

	include(signFirmware)

	sign_firmware(gateway-signed
			${VIRGIL_FIRMWARE_SIGNER_CONFIG_FILE_PATH}
			${CMAKE_BINARY_DIR}/gateway/gateway
			${GW_APP_FILE_SIZE}
			${APP_VERSION}
			${GATEWAY_MANUFACTURE}
			${GATEWAY_MODEL}
			${GW_APP_CHUNK_SIZE}
			APPL)

	add_dependencies(gateway-signed vs-tool-virgil-firmware-signer gateway)
endif()

#
# Format code
#
if(COMMAND add_clangformat)
	add_clangformat(gateway)
endif()

install(TARGETS gateway
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
