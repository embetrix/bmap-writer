cmake_minimum_required(VERSION 3.10)

# Project name
project(bmap-writer)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find pkgconfig
find_package(PkgConfig REQUIRED)

option(BUILD_STATIC "Build a statically linked binary" OFF)
if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(CMAKE_LINK_SEARCH_START_STATIC ON)
    set(CMAKE_LINK_SEARCH_END_STATIC ON)
endif()

# Find TinyXML-2
pkg_check_modules(TINYXML2 REQUIRED tinyxml2)
if(BUILD_STATIC)
    include_directories(${TINYXML2_STATIC_INCLUDE_DIRS})
    link_directories(${TINYXML2_STATIC_LIBRARY_DIRS})
    link_libraries(${TINYXML2_STATIC_LDFLAGS})
else()
    include_directories(${TINYXML2_INCLUDE_DIRS})
    link_directories(${TINYXML2_LIBRARY_DIRS})
endif()

# Find libarchive
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
if(BUILD_STATIC)
    include_directories(${LIBARCHIVE_STATIC_INCLUDE_DIRS})
    link_directories(${LIBARCHIVE_STATIC_LIBRARY_DIRS})
    link_libraries(${LIBARCHIVE_STATIC_LDFLAGS})
else()
    include_directories(${LIBARCHIVE_INCLUDE_DIRS})
    link_directories(${LIBARCHIVE_LIBRARY_DIRS})
endif()

option(USE_KERNEL_CRYPTO_API "Use the kernel crypto API to perform the hashing")
if(USE_KERNEL_CRYPTO_API)
    pkg_check_modules(LIBKCAPI REQUIRED libkcapi)
    if (LIBKCAPI_FOUND)
        if(BUILD_STATIC)
            include_directories(${LIBKCAPI_STATIC_INCLUDE_DIRS})
            link_directories(${LIBKCAPI_STATIC_LIBRARY_DIRS})
            link_libraries(${LIBKCAPI_STATIC_LDFLAGS})
        else()
            include_directories(${LIBKCAPI_INCLUDE_DIRS})
            link_directories(${LIBKCAPI_LIBRARY_DIRS})
        endif()
        if(BUILD_STATIC)
            list(APPEND CRYPTO_STATIC_LIBRARIES ${LIBKCAPI_STATIC_LIBRARIES})
        endif()
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
if(BUILD_STATIC)
    target_link_libraries(bmap-writer ${TINYXML2_STATIC_LIBRARIES} ${LIBARCHIVE_STATIC_LIBRARIES} ${CRYPTO_STATIC_LIBRARIES})
else()
    target_link_libraries(bmap-writer ${TINYXML2_LIBRARIES} ${LIBARCHIVE_LIBRARIES} ${CRYPTO_LIBRARIES})
endif()

# Specify the install rules
install(TARGETS bmap-writer DESTINATION bin)
install(PROGRAMS bmap-writer-stream.sh DESTINATION bin RENAME bmap-writer-stream)

# Enable testing
enable_testing()
add_test(NAME bmap-writer-test COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/bmap-writer-test.sh)
