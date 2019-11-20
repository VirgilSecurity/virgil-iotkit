set (GOPATH "${CMAKE_CURRENT_BINARY_DIR}/go")
file (MAKE_DIRECTORY ${GOPATH})
set (GOTMP "${GOPATH}/tmp")
file (MAKE_DIRECTORY ${GOTMP})

set(CMAKE_CGO_CFLAGS ${CGO_CFLAGS})
set(CMAKE_CGO_LDFLAGS ${CGO_LDFLAGS})

function(ExternalGoProject_Add TARG)
    add_custom_target(${TARG} env GOPATH=${GOPATH} ${CMAKE_Go_COMPILER} get ${ARGN})
endfunction(ExternalGoProject_Add)

function(add_go_executable TARGET_NAME EXECUTABLE_NAME)
    file(GLOB GO_SOURCE RELATIVE "${CMAKE_CURRENT_LIST_DIR}" "*.go")

    add_custom_target(${TARGET_NAME} ALL
            COMMAND env GOPATH=${GOPATH} CGO_CFLAGS="${CMAKE_CGO_CFLAGS}" CGO_LDFLAGS="${CMAKE_CGO_LDFLAGS}"
                    ${CMAKE_Go_COMPILER} build -o "${CMAKE_CURRENT_BINARY_DIR}/${EXECUTABLE_NAME}" ${CMAKE_GO_FLAGS} ${GO_SOURCE}
            DEPENDS virgil-crypto-go-install-deps ${ARGN}
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
            )
    add_executable(${TARGET_NAME}-target IMPORTED GLOBAL)

    set_target_properties(${TARGET_NAME}-target PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}")

    add_dependencies(${TARGET_NAME}-target ${TARGET_NAME})

    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME} DESTINATION bin)
endfunction(add_go_executable)


function(ADD_GO_LIBRARY NAME BUILD_TYPE)
    if (BUILD_TYPE STREQUAL "STATIC")
        set(BUILD_MODE -buildmode=c-archive)
        set(LIB_NAME "lib${NAME}.a")
    else ()
        set(BUILD_MODE -buildmode=c-shared)
        if (APPLE)
            set(LIB_NAME "lib${NAME}.dylib")
        else ()
            set(LIB_NAME "lib${NAME}.so")
        endif ()
    endif ()

    file(GLOB GO_SOURCE RELATIVE "${CMAKE_CURRENT_LIST_DIR}" "*.go")
    add_custom_command(OUTPUT ${OUTPUT_DIR}/.timestamp
            COMMAND env GOPATH=${GOPATH} ${CMAKE_Go_COMPILER} build ${BUILD_MODE}
            -o "${CMAKE_CURRENT_BINARY_DIR}/${LIB_NAME}"
            ${CMAKE_GO_FLAGS} ${GO_SOURCE}
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})

    add_custom_target(${NAME} ALL DEPENDS ${OUTPUT_DIR}/.timestamp ${ARGN})

    if (NOT BUILD_TYPE STREQUAL "STATIC")
        install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${LIB_NAME} DESTINATION bin)
    endif ()
endfunction(ADD_GO_LIBRARY)
