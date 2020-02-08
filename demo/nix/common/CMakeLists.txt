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

project(nix-common VERSION 0.1.0 LANGUAGES C)

#
#   Common code libraries
#
add_library(nix-common)
add_library(nix-common-firmware)

#
#	Header/Source files
#
target_sources(nix-common
		PRIVATE

		#	Headers
		${CMAKE_CURRENT_LIST_DIR}/include/sdk-impl/netif/packets-queue.h
		${CMAKE_CURRENT_LIST_DIR}/include/sdk-impl/netif/netif-udp-broadcast.h
		${CMAKE_CURRENT_LIST_DIR}/include/helpers/file-io.h
		${CMAKE_CURRENT_LIST_DIR}/include/helpers/event-group-bits.h
		${CMAKE_CURRENT_LIST_DIR}/include/helpers/msg-queue.h
		${CMAKE_CURRENT_LIST_DIR}/include/helpers/app-helpers.h
		${CMAKE_CURRENT_LIST_DIR}/include/helpers/app-storage.h
		${CMAKE_CURRENT_LIST_DIR}/include/helpers/file-cache.h

		#	Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/sdk-impl/netif/packets-queue.c
		${CMAKE_CURRENT_LIST_DIR}/src/sdk-impl/netif/netif-udp-broadcast.c
		${CMAKE_CURRENT_LIST_DIR}/src/sdk-impl/storage/storage-nix-impl.c
        ${CMAKE_CURRENT_LIST_DIR}/src/sdk-impl/logger/logger-impl.c
		${CMAKE_CURRENT_LIST_DIR}/src/helpers/file-io.c
		${CMAKE_CURRENT_LIST_DIR}/src/helpers/file-cache.c
		${CMAKE_CURRENT_LIST_DIR}/src/helpers/event-group-bits.c
		${CMAKE_CURRENT_LIST_DIR}/src/helpers/msg-queue.c
		${CMAKE_CURRENT_LIST_DIR}/src/helpers/app-helpers.c
		${CMAKE_CURRENT_LIST_DIR}/src/helpers/app-storage.c
		)

target_sources(nix-common-firmware
		PRIVATE
		#	Sources
		${CMAKE_CURRENT_LIST_DIR}/src/sdk-impl/firmware/firmware-impl.c
		)

#
#   Include directories
#
target_include_directories(nix-common
		PUBLIC
		${CMAKE_CURRENT_LIST_DIR}/include
		${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include
		PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/src
		)

target_include_directories(nix-common-firmware
		PUBLIC
		${CMAKE_CURRENT_LIST_DIR}/include
		${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include
		${VIRGIL_IOT_DIRECTORY}/modules/firmware/include
		)

#
#	Link libraries
#
find_package (Threads)
target_link_libraries(nix-common
		PUBLIC
		converters
		vs-module-secbox
		vs-module-provision
		vs-default-soft-secmodule
		${CMAKE_THREAD_LIBS_INIT}

		PRIVATE
		enable_pedantic_mode
		enable_sanitizers
		)

target_link_libraries(nix-common-firmware
		PUBLIC
		vs-default-soft-secmodule
		vs-module-firmware
		${CMAKE_THREAD_LIBS_INIT}

		PRIVATE
		enable_pedantic_mode
		enable_sanitizers
		)
#
# Format code
#
if(COMMAND add_clangformat)
	add_clangformat(nix-common)
	add_clangformat(nix-common-firmware)
endif()
