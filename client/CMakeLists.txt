cmake_minimum_required(VERSION 3.16)
project(vmp_shell LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt5 5.12 REQUIRED COMPONENTS Widgets Network)

set(CLIENT_SOURCES
    src/main.cpp
    src/app/MainWindow.cpp
    src/core/auth/AuthClient.cpp
    src/core/driver/DriverBridge.cpp
    src/core/pipeline/ProtectionPassManager.cpp
    src/core/pe/PEParser.cpp
    src/core/vm/VirtualMachine.cpp
    src/core/util/Logger.cpp
)

set(CLIENT_HEADERS
    include/app/MainWindow.h
    include/core/auth/AuthClient.h
    include/core/driver/DriverBridge.h
    include/core/pipeline/ProtectionPassManager.h
    include/core/pe/PEParser.h
    include/core/vm/VirtualMachine.h
    include/core/util/Logger.h
)

add_executable(vmp_shell ${CLIENT_SOURCES} ${CLIENT_HEADERS})

if(WIN32)
    set_target_properties(vmp_shell PROPERTIES WIN32_EXECUTABLE ON)
endif()

target_include_directories(vmp_shell
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(vmp_shell
    PRIVATE
        Qt5::Widgets
        Qt5::Network
)

if(MSVC)
    target_compile_options(vmp_shell PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(vmp_shell PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
