cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(vs-json VERSION 0.1.0 LANGUAGES C)

add_library(vs-json)

target_sources(vs-json
        PRIVATE
        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/json/json_generator.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/json/json_parser.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/json_parser.c
        ${CMAKE_CURRENT_LIST_DIR}/src/json_generator.c
        )

target_link_libraries(vs-json
        PUBLIC
        jsmn

        PRIVATE
        vs-module-logger
        )

target_include_directories(vs-json
        PRIVATE
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>

        PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

install(TARGETS vs-json
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/virgil
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )

if(COMMAND add_clangformat)
    add_clangformat(vs-json)
endif()

