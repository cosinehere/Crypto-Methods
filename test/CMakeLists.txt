message(STATUS "Enter test/")

add_executable(${cryptotest}
    ${CMAKE_CURRENT_SOURCE_DIR}/test.cpp
    )

target_link_libraries(${cryptotest}
    ${cryptolib}
    )

