cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(psp-packer)
find_package( ZLIB REQUIRED )

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

include_directories(${ZLIB_INCLUDE_DIRS})

message("zlib: " + ${ZLIB_LIBRARIES})
ADD_EXECUTABLE (psp-packer "src/psppacker.cpp" "src/packexec.cpp" "src/gzip.c" )
TARGET_LINK_LIBRARIES (psp-packer ${ZLIB_LIBRARIES})

set_property(TARGET psp-packer PROPERTY CXX_STANDARD 11)
set_property(TARGET psp-packer PROPERTY CXX_STANDARD_REQUIRED ON)
