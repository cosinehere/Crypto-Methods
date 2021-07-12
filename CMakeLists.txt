# minimum cmake version
cmake_minimum_required(VERSION 3.10)

# specify project name and version
project(CryptoMethods VERSION 1.0)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# add_subdirectory(CryptoMethods)

add_library(CryptoMethods SHARED
	#	${CMAKE_SOURCE_DIR}/CryptoMethods/pch.cpp
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

