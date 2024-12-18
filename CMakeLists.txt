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

# Find libarchive
find_package(LibArchive REQUIRED)
if (LibArchive_FOUND)
    include_directories(${LIBARCHIVE_INCLUDE_DIR})
else()
    message(FATAL_ERROR "libarchive not found")
endif()

# Add the executable
add_executable(bmap-writer bmap-writer.cpp)
target_compile_options(bmap-writer PUBLIC -Wformat -Wformat-security -Wconversion -Wsign-conversion -pedantic -Werror)

# Link the libraries
target_link_libraries(bmap-writer ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${LibArchive_LIBRARIES})

# Specify the install rules
install(TARGETS bmap-writer DESTINATION bin)

# Enable testing
enable_testing()
add_test(NAME bmap-writer-test COMMAND ./bmap-writer-test.sh)

