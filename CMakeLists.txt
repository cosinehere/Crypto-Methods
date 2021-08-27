# minimum cmake version
cmake_minimum_required(VERSION 3.16)

# specify project name and version
project(CryptoMethods
    VERSION 1.0
    LANGUAGES CXX)

# generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# global g++ compile flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

if(${CMAKE_BUILD_TYPE} MATCHES Debug)
    set(cryptolib CryptoMethods_debug)
    set(cryptotest testd)
else()
    set(cryptolib CryptoMethods)
    set(cryptotest test)
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# CryptoMethods.so
add_subdirectory(CryptoMethods)

# CryptoTest
add_subdirectory(test)

