cmake_minimum_required(VERSION 3.20)
project(windows-implant LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/CompileOptions.cmake)

add_executable(main src/main.cpp)
