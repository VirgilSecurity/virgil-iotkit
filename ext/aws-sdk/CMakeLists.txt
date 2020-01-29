cmake_minimum_required (VERSION 3.11)

project(aws-mqtt VERSION 0.1.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   Settings
# ---------------------------------------------------------------------------

#
#   Enable/Disable debug
#
option(ENABLE_IOT_INFO "Enable info messages" ON)
option(ENABLE_IOT_ERROR "Enable error messages" OFF)
option(ENABLE_IOT_WARN "Enable warning messages" OFF)
option(ENABLE_IOT_DEBUG "Enable debug messages" OFF)
option(ENABLE_IOT_TRACE "Enable trace messages" OFF)
set(MBEDTLS_DEBUG_LEVEL "0" CACHE STRING "MbedTLS debug level from 0 to 4")

# file folders
set(AWS_MQTT_ROOT     "${CMAKE_CURRENT_LIST_DIR}/aws-iot-device-sdk-embedded-C")
set(AWS_MQTT_SOURCE   "${AWS_MQTT_ROOT}/src")
set(AWS_MQTT_INCLUDE  "${AWS_MQTT_ROOT}/include")
set(AWS_MQTT_EXT_LIBS  "${AWS_MQTT_ROOT}/external_libs")

# Include and build external libraries
virgil_depends (
        PACKAGE_NAME "MbedTLS"
        CONFIG_DIR "${VIRGIL_IOT_DIRECTORY}/ext/mbedtls"
        CMAKE_ARGS "${MBEDTLS_CMAKE_ARGS}"
)

virgil_find_package (MbedTLS 2.4)

add_library(aws-sdk SHARED)

#
#   default-aws-mqtt core sources
#
file (GLOB_RECURSE AWS_MQTT_LIST_SRC "${AWS_MQTT_SOURCE}/*.c")

target_compile_definitions(aws-sdk
        PRIVATE
        $<$<CONFIG:DEBUG>:MBEDTLS_DBG_LVL=${MBEDTLS_DEBUG_LEVEL}>
        $<$<AND:$<CONFIG:DEBUG>,$<BOOL:${ENABLE_IOT_INFO}>>:ENABLE_IOT_INFO=1>
        $<$<AND:$<CONFIG:DEBUG>,$<BOOL:${ENABLE_IOT_ERROR}>>:ENABLE_IOT_ERROR=1>
        $<$<AND:$<CONFIG:DEBUG>,$<BOOL:${ENABLE_IOT_WARN}>>:ENABLE_IOT_WARN=1>
        $<$<AND:$<CONFIG:DEBUG>,$<BOOL:${ENABLE_IOT_DEBUG}>>:ENABLE_IOT_DEBUG=1>
        $<$<AND:$<CONFIG:DEBUG>,$<BOOL:${ENABLE_IOT_TRACE}>>:ENABLE_IOT_TRACE=1>
        )

target_sources(aws-sdk
        PRIVATE
        ${AWS_MQTT_LIST_SRC}
        "${CMAKE_CURRENT_LIST_DIR}/platform/common/timer.c"
        "${CMAKE_CURRENT_LIST_DIR}/platform/mbedtls/network_mbedtls_wrapper.c"
        "${CMAKE_CURRENT_LIST_DIR}/platform/pthread/threads_pthread_wrapper.c"
        )

target_link_libraries(aws-sdk
        mbedtls::mbedtls
        mbedtls::mbedx509
        jsmn
        )

target_include_directories (aws-sdk
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}"
        "${AWS_MQTT_INCLUDE}"
        "${CMAKE_CURRENT_LIST_DIR}/platform/common"
        "${CMAKE_CURRENT_LIST_DIR}/platform/mbedtls"
        "${CMAKE_CURRENT_LIST_DIR}/platform/pthread"

        INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

install(TARGETS aws-sdk
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(DIRECTORY ${AWS_MQTT_INCLUDE}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/aws-sdk
        )
