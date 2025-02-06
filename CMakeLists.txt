cmake_minimum_required(VERSION 3.10)

# Project name
project(bmap-writer)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find pkgconfig
find_package(PkgConfig REQUIRED)

# Find TinyXML-2
pkg_check_modules(TINYXML2 REQUIRED tinyxml2)
if (TINYXML2_FOUND)
    include_directories(${TINYXML2_INCLUDE_DIR})
else()
    message(FATAL_ERROR "tinyxml2 library not found")
endif()


# Find libarchive
find_package(LibArchive REQUIRED)
if (LibArchive_FOUND)
    include_directories(${LIBARCHIVE_INCLUDE_DIR})
else()
    message(FATAL_ERROR "libarchive not found")
endif()

option(USE_KERNEL_CRYPTO_API "Use the kernel crypto API to perform the hashing")
if(USE_KERNEL_CRYPTO_API)
    pkg_check_modules(LIBKCAPI REQUIRED libkcapi)
    if (LIBKCAPI_FOUND)
        include_directories(${LIBKCAPI_INCLUDE_DIRS})
        link_directories(${LIBKCAPI_LIBRARY_DIRS})
        list(APPEND CRYPTO_LIBRARIES ${LIBKCAPI_LIBRARIES})
        add_compile_definitions(USE_KERNEL_CRYPTO_API)
    else()
        message(FATAL_ERROR "libkcapi not found")
    endif()
endif()

if (NOT DEFINED DEFAULT_READ_BLK_SIZE)
  set(DEFAULT_READ_BLK_SIZE 16384)
endif()

execute_process(
    COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} describe --tags
    OUTPUT_VARIABLE GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_compile_definitions(READ_BLK_SIZE=${DEFAULT_READ_BLK_SIZE})
add_compile_definitions(GIT_VERSION="${GIT_VERSION}")

# Add the executable
add_executable(bmap-writer bmap-writer.cpp sha256.cpp)
target_compile_options(bmap-writer PUBLIC -Wformat -Wformat-security -Wconversion -Wsign-conversion -pedantic -Werror)

# Link the libraries
target_link_libraries(bmap-writer ${TINYXML2_LIBRARIES} ${LibArchive_LIBRARIES} ${CRYPTO_LIBRARIES})

# Specify the install rules
install(TARGETS bmap-writer DESTINATION bin)
install(PROGRAMS bmap-writer-stream.sh DESTINATION bin RENAME bmap-writer-stream)

# Enable testing
enable_testing()
add_test(NAME bmap-writer-test COMMAND ./bmap-writer-test.sh)
