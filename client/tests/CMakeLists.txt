cmake_minimum_required(VERSION 3.16)

include(FetchContent)
include(GoogleTest)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

set(CLIENT_TEST_SOURCES
    pe_parser_tests.cpp
)

add_executable(client_tests
    ${CLIENT_TEST_SOURCES}
)

target_sources(client_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/core/pe/PEParser.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/core/util/Logger.cpp
)

target_link_libraries(client_tests
    PRIVATE
        Qt5::Core
        gtest_main
)

target_include_directories(client_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

set_target_properties(client_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

gtest_discover_tests(client_tests)

if(MSVC)
    target_compile_options(client_tests PRIVATE /utf-8)
else()
    target_compile_options(client_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()
