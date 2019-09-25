#
# Copyright (C) 2015-2019 Virgil Security, Inc.
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
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(helpers VERSION 0.1.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   Add compiler pedantic diagnostic options
# ---------------------------------------------------------------------------
add_library(enable_pedantic_mode INTERFACE)

target_compile_options(enable_pedantic_mode
    INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:GNU>>:
            -Werror -Wall>
    )

# ---------------------------------------------------------------------------
#   Fuzzer flags
# ---------------------------------------------------------------------------
add_library(enable_fuzz_mode INTERFACE)

target_compile_definitions(enable_fuzz_mode
    INTERFACE
        $<$<BOOL:${ENABLE_FUZZY_TESTING}>:ENABLE_FUZZY_TESTING>
    )

target_compile_options(enable_fuzz_mode
    INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>>:
            -Wall -Werror -g -O1 -fsanitize=fuzzer,address -fno-omit-frame-pointer>
    )

target_link_libraries(enable_fuzz_mode
    INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>>:
            -fsanitize=fuzzer,address>
    )

# ---------------------------------------------------------------------------
#   Address sanitizer flags
# ---------------------------------------------------------------------------
message("-- Address Sanitizer: ${USE_ASAN}")

add_library(enable_asan_mode INTERFACE)

target_compile_options(enable_asan_mode
    INTERFACE
        -fno-omit-frame-pointer -fsanitize=address
    )

target_link_libraries(enable_asan_mode
    INTERFACE
        -fno-omit-frame-pointer -fsanitize=address
    )

# ---------------------------------------------------------------------------
#   Undefined behavior sanitizer flags
# ---------------------------------------------------------------------------
message("-- Undefined behavior Sanitizer: ${USE_UBSAN}")

add_library(enable_ubsan_mode INTERFACE)

target_compile_options(enable_ubsan_mode
    INTERFACE
        -fsanitize=undefined
    )

target_link_libraries(enable_ubsan_mode
    INTERFACE
        -fsanitize=undefined
    )

# ---------------------------------------------------------------------------
#   Thread sanitizer flags
# ---------------------------------------------------------------------------
message("-- Thread Sanitizer: ${USE_TSAN}")

add_library(enable_tsan_mode INTERFACE)

target_compile_options(enable_tsan_mode
        INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>, $<C_COMPILER_ID:GNU>>:
        -fno-omit-frame-pointer -fsanitize=thread>
        )

target_link_libraries(enable_tsan_mode
        INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>, $<C_COMPILER_ID:GNU>>:
        -fno-omit-frame-pointer -fsanitize=thread>
        )

# ---------------------------------------------------------------------------
#   Memory sanitizer flags
# ---------------------------------------------------------------------------
message("-- Memory Sanitizer: ${USE_MSAN}")

add_library(enable_msan_mode INTERFACE)

target_compile_options(enable_msan_mode
        INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>, $<C_COMPILER_ID:GNU>>:
        -fno-omit-frame-pointer -fsanitize=memory>
        )

target_link_libraries(enable_msan_mode
        INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>, $<C_COMPILER_ID:GNU>>:
        -fno-omit-frame-pointer -fsanitize=memory>
        )

# ---------------------------------------------------------------------------
#   Leak sanitizer flags
# ---------------------------------------------------------------------------
message("-- Leak Sanitizer: ${USE_LSAN}")

add_library(enable_lsan_mode INTERFACE)

target_compile_options(enable_lsan_mode
        INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>, $<C_COMPILER_ID:GNU>>:
        -fno-omit-frame-pointer -fsanitize=leak>
        )

target_link_libraries(enable_lsan_mode
        INTERFACE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>, $<C_COMPILER_ID:GNU>>:
        -fno-omit-frame-pointer -fsanitize=leak>
        )

# ---------------------------------------------------------------------------
#   Sanitizer target
# ---------------------------------------------------------------------------
add_library(enable_sanitizers INTERFACE)

target_link_libraries(enable_sanitizers
        INTERFACE
        $<$<BOOL:${USE_ASAN}>:enable_asan_mode>
        $<$<BOOL:${USE_TSAN}>:enable_tsan_mode>
        $<$<BOOL:${USE_MSAN}>:enable_msan_mode>
        $<$<BOOL:${USE_LSAN}>:enable_lsan_mode>
        $<$<BOOL:${USE_UBSAN}>:enable_ubsan_mode>
        )
