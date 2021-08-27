message(STATUS "Enter CryptoMethods/")

add_library(${cryptolib} SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/AES.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/DES.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TripDES.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Blowfish.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Twofish.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Camellia.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/RC5.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/RC6.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SM4.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoMethodDefines.cpp
    )

target_precompile_headers(${cryptolib}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/pch.h
    )

target_compile_options(${cryptolib}
    PRIVATE -fvisibility=hidden
    )

target_link_options(${cryptolib}
    PRIVATE -Wl,-s
    )

