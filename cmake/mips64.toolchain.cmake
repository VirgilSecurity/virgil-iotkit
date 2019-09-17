cmake_minimum_required (VERSION 3.11)

# Define target system
#set (CMAKE_CROSSCOMPILING TRUE)
set (CMAKE_SYSTEM_NAME Linux)
set (CMAKE_SYSTEM_PROCESSOR mips)

set (MIPS_GNU_INSTALL_ROOT "/opt/mips-img-linux-gnu/2018.09-03")

# Define toolchain executable prefix
set (MIPS_GNU_PREFIX "mips-img-linux-gnu" CACHE STRING "MIPS GNU executable prefix")

# Define executable suffix
#set (CMAKE_EXECUTABLE_SUFFIX ".mips")

# Define crosscompile
include(CMakeForceCompiler)
set(CMAKE_C_COMPILER ${MIPS_GNU_INSTALL_ROOT}/bin/${MIPS_GNU_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${MIPS_GNU_INSTALL_ROOT}/bin/${MIPS_GNU_PREFIX}-g++)

# Define target environment
set (CMAKE_FIND_ROOT_PATH ${MIPS_GNU_INSTALL_ROOT})

#set (CMAKE_MAKE_PROGRAM "make")

# Define compilation and linkage flags
set (CMAKE_C_FLAGS                  "-march=mips64r6 -mabi=64" CACHE STRING "")
set (CMAKE_CXX_FLAGS                "-march=mips64r6 -mabi=64" CACHE STRING "")
set (CMAKE_EXE_LINKER_FLAGS         ""  CACHE STRING "")

# Define processor specific compilation flags
set (SYSTEM_PROCESSOR_FLAGS "")

set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   ${SYSTEM_PROCESSOR_FLAGS}" CACHE STRING "" FORCE)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SYSTEM_PROCESSOR_FLAGS}" CACHE STRING "" FORCE)

# Define search path behaviour for includes, libraries and executables
set (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
