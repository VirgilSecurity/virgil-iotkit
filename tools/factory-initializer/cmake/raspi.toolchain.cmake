SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_VERSION 1)

SET(TOOLROOT $ENV{HOME}/soft/tools/arm-bcm2708/arm-rpi-4.9.3-linux-gnueabihf)
SET(PIROOT $ENV{HOME}/pi3/root)

# Specify the cross compiler
SET(CMAKE_C_COMPILER   ${TOOLROOT}/bin/arm-linux-gnueabihf-gcc)
SET(CMAKE_CXX_COMPILER ${TOOLROOT}/bin/arm-linux-gnueabihf-g++)


# Where is the target environment
SET(CMAKE_FIND_ROOT_PATH ${PIROOT})
LINK_DIRECTORIES(
		/usr/lib/arm-linux-gnueabihf 
		/lib/arm-linux-gnueabihf
		)

INCLUDE_DIRECTORIES(
		${PIROOT}/usr/include 
		${PIROOT}/usr/local/include 
		)

# Search for programs only in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search for libraries and headers only in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

