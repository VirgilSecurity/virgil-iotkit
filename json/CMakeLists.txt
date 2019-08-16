cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(vs-json VERSION 0.1.0 LANGUAGES C)

add_library(vs-json)

target_sources(vs-json
        PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src/json_parser.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/json_generator.c"
        )

target_link_libraries(vs-json
        PUBLIC
        jsmn
        )

target_include_directories(vs-json
        PRIVATE
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>

        PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
        )
