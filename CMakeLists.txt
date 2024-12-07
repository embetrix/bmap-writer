cmake_minimum_required(VERSION 3.10)

# Project name
project(bmap-writer)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find libxml2
find_package(LibXml2 REQUIRED)
if (LIBXML2_FOUND)
    include_directories(${LIBXML2_INCLUDE_DIR})
else()
    message(FATAL_ERROR "libxml2 not found")
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

# Find zlib
find_package(ZLIB REQUIRED)
if (ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "zlib not found")
endif()

# Find liblzma
find_package(LibLZMA REQUIRED)
if (LIBLZMA_FOUND)
    include_directories(${LIBLZMA_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "liblzma not found")
endif()

# Add the executable
add_executable(bmap-writer bmap-writer.cpp)
target_compile_options(bmap-writer PUBLIC -Wformat -Wformat-security -Wconversion -Wsign-conversion -pedantic -Werror)

# Link the libraries
target_link_libraries(bmap-writer ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} ${LIBLZMA_LIBRARIES})

# Specify the install rules
install(TARGETS bmap-writer DESTINATION bin)

# Enable testing
enable_testing()
add_test(NAME bmap-writer-test COMMAND ./bmap-writer-test.sh)

