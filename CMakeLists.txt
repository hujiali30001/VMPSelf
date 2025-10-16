cmake_minimum_required(VERSION 3.16)

project(VMPSelf LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
if(BUILD_TESTING)
    enable_testing()
endif()

option(BUILD_CLIENT "Build Qt client" ON)
option(BUILD_SERVER "Build backend utilities" ON)

if(BUILD_CLIENT)
    add_subdirectory(client)
endif()

if(BUILD_SERVER)
    add_subdirectory(server)
endif()
