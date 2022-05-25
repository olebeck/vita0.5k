cmake_minimum_required(VERSION 3.0.0)
project(cpp-vita VERSION 0.1.0)

include(CTest)
enable_testing()

file(GLOB SRCS "src/*.cpp")

add_executable(cpp-vita ${SRCS} src/_keys.h)

find_library(BOTAN NAMES BOTAN2 botan2 botan-2 BOTAN botan REQUIRED)
target_link_libraries(cpp-vita z ${BOTAN} unicorn)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdiagnostics-color=always")

add_custom_command(OUTPUT ${CMAKE_CURRENT_LIST_DIR}/src/_keys.h
    COMMAND python generate_keys.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
