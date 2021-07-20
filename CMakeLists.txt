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
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall")

# CryptoMethods.so
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
add_library(CryptoMethods SHARED
	#${CMAKE_SOURCE_DIR}/CryptoMethods/pch.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/AES.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/DES.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/TripDES.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/Blowfish.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/Twofish.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/Camellia.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/RC5.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/RC6.cpp
	${CMAKE_SOURCE_DIR}/CryptoMethods/CryptoMethodDefines.cpp
	)
target_precompile_headers(CryptoMethods PUBLIC
	${CMAKE_SOURCE_DIR}/CryptoMethods/pch.h)
set_target_properties(CryptoMethods PROPERTIES COMPILE_FLAGS "-fvisibility=hidden -Wl,-s")

# CryptoTest
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
add_executable(CryptoTest
	${CMAKE_SOURCE_DIR}/test/test.cpp
	)
target_link_libraries(CryptoTest CryptoMethods)

